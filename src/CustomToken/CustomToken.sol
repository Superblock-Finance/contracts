// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/draft-ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

contract CustomToken is Initializable, ERC20Upgradeable, ERC20BurnableUpgradeable, ERC20PausableUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant FREEZER_ROLE = keccak256("FREEZER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    mapping(address => bool) private _frozenAccounts;
    mapping(address => bool) private _blacklistedAccounts;

    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed account, uint256 amount);
    event Freeze(address indexed account);
    event Unfreeze(address indexed account);
    event Blacklist(address indexed account);
    event Unblacklist(address indexed account);
    event Pause();
    event Unpause();
    event WithdrawEther(address indexed account, uint256 amount);
    event WithdrawERC20(address indexed token, address indexed account, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(string memory name, string memory symbol, address admin) initializer public {
        __ERC20_init(name, symbol);
        __ERC20Burnable_init();
        __ERC20Pausable_init();
        __AccessControl_init();
        __ERC20Permit_init(name);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(BURNER_ROLE, admin);
        _grantRole(FREEZER_ROLE, admin);
        _grantRole(BLACKLISTER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
        emit Mint(to, amount);
    }

    function burn(address account, uint256 amount) public onlyRole(BURNER_ROLE) {
        _burn(account, amount);
        emit Burn(account, amount);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
        emit Pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
        emit Unpause();
    }

    function freeze(address account) public onlyRole(FREEZER_ROLE) {
        _frozenAccounts[account] = true;
        emit Freeze(account);
    }

    function unfreeze(address account) public onlyRole(FREEZER_ROLE) {
        _frozenAccounts[account] = false;
        emit Unfreeze(account);
    }

    function isFrozen(address account) public view returns (bool) {
        return _frozenAccounts[account];
    }

    function blacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _blacklistedAccounts[account] = true;
        emit Blacklist(account);
    }

    function unblacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _blacklistedAccounts[account] = false;
        emit Unblacklist(account);
    }

    function isBlacklisted(address account) public view returns (bool) {
        return _blacklistedAccounts[account];
    }

    // The following functions are overrides required by Solidity.

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20Upgradeable, ERC20PausableUpgradeable)
    {
        require(!_frozenAccounts[from], "Sender account is frozen");
        require(!_frozenAccounts[to], "Recipient account is frozen");
        require(!_blacklistedAccounts[from], "Sender account is blacklisted");
        require(!_blacklistedAccounts[to], "Recipient account is blacklisted");
        super._update(from, to, value);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    // Withdraw Ether from the contract
    function withdrawEther(uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE) {
        require(amount <= address(this).balance, "Insufficient balance in contract");
        payable(_msgSender()).transfer(amount);
        emit WithdrawEther(_msgSender(), amount);
    }

    // Withdraw ERC20 tokens from the contract
    function withdrawERC20(address tokenAddress, uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE) {
        IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
        uint256 balance = token.balanceOf(address(this));
        require(amount <= balance, "Insufficient balance in the contract");
        token.safeTransfer(_msgSender(), amount);
        emit WithdrawERC20(tokenAddress, _msgSender(), amount);
    }

    // Fallback and receive functions to handle Ether transfers
    receive() external payable {
        revert("Direct transfers not allowed");
    }

    fallback() external payable {
        revert("Direct transfers not allowed");
    }
}
