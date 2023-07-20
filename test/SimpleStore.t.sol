// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.15;

import "foundry-huff/HuffDeployer.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract SimpleStoreTest is Test {
    /// @dev Address of the SimpleStore contract.
    SimpleStore public simpleStore;

    /// @dev Setup the testing environment.
    function setUp() public {
        simpleStore = SimpleStore(HuffDeployer.deploy("SimpleStore"));
    }

    /// @dev Ensure that you can set and get the value.
    function testSetAndGetValue(uint256 value) public {
        simpleStore.setValue(value);
        console.log(value);
        console.log(simpleStore.getValue());
        assertEq(value, simpleStore.getValue());
    }

    /// @dev Call 'helloWorld()' and ensure it returns "Hello, World!"
    function testHelloWorld() public {
        string memory helloWorld = simpleStore.helloWorld();
        console.log(helloWorld);
        assertEq(helloWorld, "Hello, World!");
    }

    /// @dev Call 'longString()' and ensure it returns the correct long string
    function testLongString() public {
        string memory longString = simpleStore.longString();
        console.log(longString);
        assertEq(
            longString,
            "Lorem ipsum dolor sit amet, qui minim labore adipisicing minim sint cillum sint consectetur cupidatat."
        );
    }

    /// @dev Call non existant function and ensure it reverts for 'NotFound' when no matching selector is found
    function testNotFound(bytes4 sel) public {
        vm.expectRevert(
            abi.encodeWithSelector(SimpleStore.NotFound.selector, sel)
        );
        address(simpleStore).call(abi.encodeWithSelector(sel));
    }

    event RecievedPayment(address indexed sender, uint256 value);

    /// @dev Send ETH to contract without matching selector and check for 'RecievedPayment' event
    function testRecieve(address caller, uint256 value) public {
        vm.assume(value > 0);

        vm.startPrank(caller);
        vm.deal(caller, value);

        vm.expectEmit(true, true, false, true);
        emit RecievedPayment(caller, value);
        simpleStore.nonExistant{value: value}();

        vm.stopPrank();
    }

    uint internal constant Q =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // @dev test 'prefixMessage' and 'recover' functions and ensure it returns the correct public key address
    function testRecover(uint256 pkSeed, bytes32 hash) public {
        vm.assume(pkSeed != 0);
        uint256 privKey = bound(pkSeed, 1, Q - 1);

        address publicKey = vm.addr(privKey);

        bytes32 prefixedHash = simpleStore.prefixMessage(hash);
        assertEq(
            prefixedHash,
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            ),
            "mismatched hashes"
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, prefixedHash);
        address recoveredAddr = simpleStore.recover(hash, v, r, s);
        assertEq(recoveredAddr, publicKey, "mismatched addresses");
    }

    // @dev test that 'recover' returns address(0) if input signature is invalid
    function testCannotRecoverInvalidSig(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        vm.assume(
            v > 28 ||
                v < 27 ||
                s >=
                0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
        );

        address recoveredAddr = simpleStore.recover(hash, v, r, s);
        assertEq(recoveredAddr, address(0), "recovered should be address(0)");
    }
}

interface SimpleStore {
    error NotFound(bytes4);

    event RecievedPayment(address indexed, uint256);

    function nonExistant() external payable;

    function setValue(uint256) external;

    function getValue() external returns (uint256);

    function helloWorld() external returns (string memory);

    function longString() external returns (string memory);

    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (address);

    function prefixMessage(bytes32) external view returns (bytes32);
}
