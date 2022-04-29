// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

/// @title Trustus
/// @author zefram.eth
/// @notice Trust-minimized method for accessing offchain data onchain
abstract contract Trustus {
    /// -----------------------------------------------------------------------
    /// Structs
    /// -----------------------------------------------------------------------

    /// @param v Part of the ECDSA signature
    /// @param r Part of the ECDSA signature
    /// @param s Part of the ECDSA signature
    /// @param request Identifier for verifying the packet is what is desired
    /// , rather than a packet for some other function/contract
    /// @param deadline The Unix timestamp (in seconds) after which the packet
    /// should be rejected by the contract
    /// @param payload The payload of the packet
    struct TrustusPacket {
        uint8 v;
        bytes32 r;
        bytes32 s;
        address request;
        uint256 deadline;
        address receiver;
    }

    /// -----------------------------------------------------------------------
    /// Errors
    /// -----------------------------------------------------------------------

    error Trustus__InvalidPacket();

    /// -----------------------------------------------------------------------
    /// Immutable parameters
    /// -----------------------------------------------------------------------

    /// @notice The chain ID used by EIP-712
    uint256 internal immutable INITIAL_CHAIN_ID;

    /// @notice The domain separator used by EIP-712
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    /// -----------------------------------------------------------------------
    /// Storage variables
    /// -----------------------------------------------------------------------

    /// @notice Records whether an address is trusted as a packet provider
    /// @dev provider => value
    mapping(address => bool) internal isTrusted;

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    /// @notice Verifies whether a packet is valid and returns the result.
    /// Will revert if the packet is invalid.
    /// @dev The deadline, request, and signature are verified.
    /// @param request The identifier for the requested payload
    /// @param packet The packet provided by the offchain data provider
    modifier verifyPacket(address request, TrustusPacket calldata packet) {
        if (!_verifyPacket(request, packet)) revert Trustus__InvalidPacket();
        _;
    }

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    constructor() {
        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    /// -----------------------------------------------------------------------
    /// Packet verification
    /// -----------------------------------------------------------------------

    /// @notice Verifies whether a packet is valid and returns the result.
    /// @dev The deadline, request, and signature are verified.
    /// @param request The identifier for the requested payload
    /// @param packet The packet provided by the offchain data provider
    /// @return success True if the packet is valid, false otherwise
    function _verifyPacket(address request, TrustusPacket calldata packet)
        internal
        virtual
        returns (bool success)
    {
        // verify deadline
        if (block.timestamp > packet.deadline) return false;

        // verify request
        if (request != packet.request) return false;

        // verify signature
        address recoveredAddress = ecrecover(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "VerifyPacket(address request,uint256 deadline,address receiver)"
                            ),
                            packet.request,
                            packet.deadline,
                            packet.receiver
                        )
                    )
                )
            ),
            packet.v,
            packet.r,
            packet.s
        );
        return (recoveredAddress != address(0)) && isTrusted[recoveredAddress];
    }

    /// @notice Sets the trusted status of an offchain data provider.
    /// @param signer The data provider's ECDSA public key as an Ethereum address
    /// @param isTrusted_ The desired trusted status to set
    function _setIsTrusted(address signer, bool isTrusted_) internal virtual {
        isTrusted[signer] = isTrusted_;
    }

    /// -----------------------------------------------------------------------
    /// EIP-712 compliance
    /// -----------------------------------------------------------------------

    /// @notice The domain separator used by EIP-712
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return
            block.chainid == INITIAL_CHAIN_ID
                ? INITIAL_DOMAIN_SEPARATOR
                : _computeDomainSeparator();
    }

    /// @notice Computes the domain separator used by EIP-712
    function _computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    ),
                    keccak256("Web3Game"),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }
}
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)



// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)



/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
///@title ClaimManager
///@author nutcloud🧙‍♂️.eth
///@notice Claim manager abstract contract to handle reward claiming logic
abstract contract ClaimManager {
    ///-------------------------------------------------------
    ///	Storage variables
    ///-------------------------------------------------------

    /// @notice The address of the claim verifier contract
    address public immutable claimVerifier;

    ///-------------------------------------------------------
    ///	Constructor
    ///-------------------------------------------------------

    constructor (address _claimVerifier) {
        claimVerifier = _claimVerifier;
    }

    ///-------------------------------------------------------
    ///	Claim authority logic
    ///-------------------------------------------------------

    /// @notice Verifies if the caller is the claim verifier contract
    /// @param claimer Address of the claimer
    function claim(address claimer) external {
        require(msg.sender == claimVerifier, "ClaimManager: sender not claim verifier");
        _claim(claimer);
    }

    ///-------------------------------------------------------
    ///	Internal claim logic
    ///-------------------------------------------------------

    /// @notice This contains all the logic for distributing rewards to the claimer
    /// @param claimer Address of the claimer
    function _claim(address claimer) internal virtual;
}

/// @title Claim
/// @author nutcloud🧙‍♂️.eth
/// @notice Verifier contract for claiming rewards based on off-chain events using zefram.eth's Trustus
contract ClaimVerifier is Trustus, Ownable {
    ///-------------------------------------------------------
    ///	Storage
    ///-------------------------------------------------------

    /// @notice Records whether a contract is a valid claimManager
    mapping(ClaimManager => bool) public isClaimManager;

    ///-------------------------------------------------------
    ///	Events
    ///-------------------------------------------------------

    /// @notice Emitted everytime a contract is added or removed as a valid claim manager
    event UpdatedClaimManager(
        address indexed claimManager,
        bool isClaimManager
    );

    /// @notice Emitted everytime an address is added or removed as a trusted signer
    event UpdatedTrustedSigner(address indexed signer, bool isTrusted);

    /// @notice Emitted everytime an address claims
    event Claimed(address indexed claimer, address indexed claimManager);

    ///-------------------------------------------------------
    ///	Constructor
    ///-------------------------------------------------------
    constructor() Ownable() {}

    ///-------------------------------------------------------
    ///	Claim manager addition/removal logic
    ///-------------------------------------------------------

    /// @notice Add or remove a contract as a valid claim manager
    /// @dev Set isClaimManager_ true to add, false to remove
    /// @param claimManager Address of the claim manager to contract to add/remove
    /// @param isClaimManager_ Flag to add or remove the contract given as a claim manager
    function setIsClaimManager(ClaimManager claimManager, bool isClaimManager_)
        external
        onlyOwner
    {
        require(
            address(claimManager) != address(0),
            "ClaimVerifier: zero address"
        );

        isClaimManager[claimManager] = isClaimManager_;

        emit UpdatedClaimManager(address(claimManager), isClaimManager_);
    }

    ///-------------------------------------------------------
    ///	Claim manager addition/removal logic
    ///-------------------------------------------------------

    /// @notice Add or remove an address as a trusted signer
    /// @dev set isTrusted to true to add, false to remove
    /// @param signer The address to add/remove as a trusted signer
    /// @param isTrusted The flag to add or remove the address
    function setIsTrusted(address signer, bool isTrusted) external onlyOwner {
        _setIsTrusted(signer, isTrusted);

        emit UpdatedTrustedSigner(signer, isTrusted);
    }

    ///-------------------------------------------------------
    ///	Claim logic
    ///-------------------------------------------------------

    /// @notice Public function to claim
    /// @param request The identifier for the requested payload. this can be the claim manager address
    /// @param packet The packet containing the claim manager address and the address of the claimer provided by the off-chain server
    function claim(address request, TrustusPacket calldata packet)
        external
        verifyPacket(request, packet)
    {
        require(packet.receiver == msg.sender, "ClaimManager: not your packet");

        ClaimManager claimManager = ClaimManager(request);
        require(
            isClaimManager[claimManager],
            "ClaimManager: invalid claim manager address"
        );

        claimManager.claim(packet.receiver);

        emit Claimed(packet.receiver, request);
    }
}
