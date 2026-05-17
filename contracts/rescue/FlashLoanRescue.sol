// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FlashLoanRescue
/// @notice Aave v3 simple flash-loan receiver that runs a pre-encoded
///         drain plan inside the callback, repays the loan, and forwards
///         the remaining balance to a designated escrow.
///
/// Wire-up:
///   1. Deploy per-chain. The `pool` constructor arg must be the Aave v3
///      Pool address for that chain (see panel/src/server/sim/rescue-prove.ts
///      AAVE_V3_POOL_BY_CHAIN for canonical addresses).
///   2. Register the deployed address in the panel's `.env` under
///      RESCUE_FLASHLOAN_RECEIVER as "chainId:address,...".
///   3. The panel's broadcaster, when handling a PoE with verdict
///      `requires_flashloan_helper`, will call `executeRescue(...)` on
///      this contract with the borrow params + drain plan; the contract
///      handles the rest.
///
/// Authorization model: only `owner` can invoke `executeRescue`. We use a
/// minimal owner pattern instead of pulling in OpenZeppelin to keep this
/// trivially auditable. Transfer ownership to a Safe in production.
///
/// Reentrancy: not needed — the only external calls during execution are
/// initiated by Aave's executeOperation callback which is guarded by Aave.
/// Drain calls are made one at a time within executeOperation. If a drain
/// call calls back into us, the require(msg.sender == pool) gates new
/// flashLoanSimple invocations.

interface IAaveV3Pool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract FlashLoanRescue {
    IAaveV3Pool public immutable pool;
    address public owner;

    event Rescued(address indexed escrow, address indexed asset, uint256 surplus);
    event StepResult(uint256 indexed index, bool success, bytes returnData);

    error NotOwner();
    error NotPool();
    error BadInitiator();
    error StepReverted(uint256 index, bytes data);
    error InsufficientForRepay(uint256 needed, uint256 have);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _pool) {
        pool = IAaveV3Pool(_pool);
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Kick off a flash-loan-funded rescue. Called by the panel
    ///         broadcaster (whose key must be `owner`).
    /// @param asset      Borrow asset (e.g. WETH on mainnet).
    /// @param amount     Borrow amount.
    /// @param targets    Per-step `to` addresses for the drain plan.
    /// @param calldatas  Per-step `data` blobs.
    /// @param values     Per-step `value` (in wei). Native is sent from
    ///                   this contract's balance; pre-fund or borrow native via WETH
    ///                   unwrap inside a drain step.
    /// @param escrow     Final destination of surplus after loan repayment.
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
        bytes memory params = abi.encode(targets, calldatas, values, escrow);
        pool.flashLoanSimple(address(this), asset, amount, params, 0);
    }

    /// @notice Aave v3 callback. Runs the drain plan and repays the loan.
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        if (msg.sender != address(pool)) revert NotPool();
        if (initiator != address(this)) revert BadInitiator();

        (
            address[] memory targets,
            bytes[] memory calldatas,
            uint256[] memory values,
            address escrow
        ) = abi.decode(params, (address[], bytes[], uint256[], address));

        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(calldatas[i]);
            emit StepResult(i, ok, ret);
            // We deliberately do NOT revert on per-step failure — the
            // operator may have queued multiple drain candidates of
            // which only one is expected to succeed. The post-repay
            // surplus check below catches the case where no step
            // actually moved value.
        }

        // Repay loan + fee.
        uint256 totalOwed = amount + premium;
        uint256 selfBalance = IERC20(asset).balanceOf(address(this));
        if (selfBalance < totalOwed) revert InsufficientForRepay(totalOwed, selfBalance);
        IERC20(asset).approve(address(pool), totalOwed);

        // Sweep surplus to escrow.
        uint256 surplus = selfBalance - totalOwed;
        if (surplus > 0) {
            IERC20(asset).transfer(escrow, surplus);
            emit Rescued(escrow, asset, surplus);
        }
        return true;
    }

    /// @notice Rescue stuck tokens that didn't sweep automatically (e.g.
    ///         drain plan brought in a different ERC-20 than the loan asset).
    function sweep(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
    }

    /// @notice Sweep native ETH that lands here from drain steps that unwrap WETH.
    function sweepNative(address payable to, uint256 amount) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "native sweep failed");
    }

    receive() external payable {}
    fallback() external payable {}
}
