// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FlashSwapRescue
/// @notice UniswapV2-style flash-swap receiver that runs a drain plan
///         inside the swap callback, repays the flash swap, and forwards
///         remaining balance to escrow.
///
/// For chains WITHOUT Aave v3 (Sonic, Blast, etc.) that still have
/// UniswapV2-compatible DEXes (SpookySwap, Thruster, etc.).
///
/// Wire-up:
///   1. Deploy per-chain. The `factory` constructor arg must be the UniV2
///      factory address for that chain's primary DEX.
///   2. Register in RESCUE_FLASHLOAN_RECEIVER as "chainId:address,..."
///      (same env var as the Aave variant — the broadcaster doesn't care
///      which flash-loan mechanism is used under the hood).
///   3. The broadcaster calls `executeRescue(...)` identically to the Aave
///      variant. This contract adapts the interface to UniV2 flash swaps.
///
/// How UniV2 flash swaps work:
///   - Call pair.swap(amount0Out, amount1Out, to=this, data=non-empty)
///   - Pair sends tokens to `this` BEFORE the callback
///   - Pair calls uniswapV2Call(sender, amount0, amount1, data) on `this`
///   - Inside the callback we execute the drain plan + repay
///   - Pair verifies K-constant invariant after callback returns
///
/// Authorization: same minimal owner pattern as FlashLoanRescue.sol.

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IUniswapV2Factory {
    function getPair(address tokenA, address tokenB) external view returns (address);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract FlashSwapRescue {
    IUniswapV2Factory public immutable factory;
    address public owner;

    event Rescued(address indexed escrow, address indexed asset, uint256 surplus);
    event StepResult(uint256 indexed index, bool success, bytes returnData);

    error NotOwner();
    error NotPair();
    error InsufficientForRepay(uint256 needed, uint256 have);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _factory) {
        factory = IUniswapV2Factory(_factory);
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Kick off a flash-swap-funded rescue.
    /// @dev Same interface as FlashLoanRescue.executeRescue for broadcaster compatibility.
    /// @param asset      The token to flash-borrow (e.g. WETH).
    /// @param amount     Flash-borrow amount.
    /// @param targets    Per-step `to` addresses.
    /// @param calldatas  Per-step `data` blobs.
    /// @param values     Per-step `value` (native wei).
    /// @param escrow     Final destination of surplus.
    function executeRescue(
        address asset,
        uint256 amount,
        address[] calldata targets,
        bytes[] calldata calldatas,
        uint256[] calldata values,
        address escrow
    ) external onlyOwner {
        require(targets.length == calldatas.length, "len mismatch t/c");
        require(targets.length == values.length, "len mismatch t/v");
        _doFlashSwap(asset, amount, abi.encode(targets, calldatas, values, escrow, asset, amount));
    }

    function _doFlashSwap(address asset, uint256 amount, bytes memory params) internal {
        address pair = _findPairForAsset(asset);
        require(pair != address(0), "no pair found for asset");

        uint a0;
        uint a1;
        if (IUniswapV2Pair(pair).token0() == asset) {
            a0 = amount;
        } else {
            a1 = amount;
        }
        IUniswapV2Pair(pair).swap(a0, a1, address(this), params);
    }

    /// @notice UniswapV2 flash swap callback.
    /// Called by the pair after sending us the flash-borrowed tokens.
    function uniswapV2Call(
        address sender,
        uint /* amount0 */,
        uint /* amount1 */,
        bytes calldata data
    ) external {
        _executeFlashCallback(sender, data);
    }

    /// @notice Some DEXes use different callback names
    function pancakeCall(address sender, uint, uint, bytes calldata data) external {
        _executeFlashCallback(sender, data);
    }

    function swapV2Call(address sender, uint, uint, bytes calldata data) external {
        _executeFlashCallback(sender, data);
    }

    function _executeFlashCallback(address sender, bytes calldata data) internal {
        require(sender == address(this), "invalid sender");

        (
            address[] memory targets,
            bytes[] memory calldatas,
            uint256[] memory values,
            address escrow,
            address asset,
            uint256 borrowedAmount
        ) = abi.decode(data, (address[], bytes[], uint256[], address, address, uint256));

        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(calldatas[i]);
            emit StepResult(i, ok, ret);
        }

        // Repay: UniV2 requires amount * 1000/997 (0.3% fee)
        uint256 repayAmount = (borrowedAmount * 1000 / 997) + 1;
        uint256 selfBalance = IERC20(asset).balanceOf(address(this));
        if (selfBalance < repayAmount) revert InsufficientForRepay(repayAmount, selfBalance);

        // Send repayment directly to the pair (msg.sender)
        IERC20(asset).transfer(msg.sender, repayAmount);

        // Sweep surplus to escrow
        uint256 remaining = IERC20(asset).balanceOf(address(this));
        if (remaining > 0) {
            IERC20(asset).transfer(escrow, remaining);
            emit Rescued(escrow, asset, remaining);
        }
    }

    function _findPairForAsset(address asset) internal view returns (address) {
        address wNative = _tryGetWNative();
        if (wNative != address(0) && wNative != asset) {
            address pair = IUniswapV2Factory(factory).getPair(asset, wNative);
            if (pair != address(0)) return pair;
        }
        address usdc = _stableForChain();
        if (usdc != address(0) && usdc != asset) {
            address pair = IUniswapV2Factory(factory).getPair(asset, usdc);
            if (pair != address(0)) return pair;
        }
        address usdt = _usdtForChain();
        if (usdt != address(0) && usdt != asset) {
            address pair = IUniswapV2Factory(factory).getPair(asset, usdt);
            if (pair != address(0)) return pair;
        }
        return address(0);
    }

    function _tryGetWNative() internal view returns (address) {
        uint256 chainId;
        assembly { chainId := chainid() }
        if (chainId == 146) return 0x039e2fB66102314Ce7b64Ce5Ce3E5183bc94aD38;
        if (chainId == 81457) return 0x4300000000000000000000000000000000000004;
        if (chainId == 1) return 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        if (chainId == 56) return 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
        return address(0);
    }

    function _stableForChain() internal view returns (address) {
        uint256 chainId;
        assembly { chainId := chainid() }
        if (chainId == 146) return 0x29219dd400f2Bf60E5a23d13Be72B486D4038894;
        if (chainId == 81457) return 0x4300000000000000000000000000000000000003;
        if (chainId == 1) return 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        if (chainId == 56) return 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
        return address(0);
    }

    function _usdtForChain() internal view returns (address) {
        uint256 chainId;
        assembly { chainId := chainid() }
        if (chainId == 1) return 0xdAC17F958D2ee523a2206206994597C13D831ec7;
        if (chainId == 56) return 0x55d398326f99059fF775485246999027B3197955;
        return address(0);
    }

    function sweep(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
    }

    function sweepNative(address payable to, uint256 amount) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "native sweep failed");
    }

    receive() external payable {}
    fallback() external payable {}
}
