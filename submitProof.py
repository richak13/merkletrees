import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import geth_poa_middleware  # Necessary for POA chains
from Crypto.Hash import keccak

def merkle_assignment():
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)
    leaves = convert_leaves(primes)
    tree = build_merkle(leaves)
    
    random_leaf_index = 1  # Use a random unclaimed index here
    proof = prove_merkle(tree, random_leaf_index)
    
    challenge = ''.join(random.choice(string.ascii_letters) for i in range(32))
    addr, sig = sign_challenge(challenge)
    
    if sign_challenge_verify(challenge, addr, sig):
        tx_hash = send_signed_msg(proof, leaves[random_leaf_index])
        print(f"Transaction hash: {tx_hash}")

def generate_primes(num_primes):
    primes_list = []
    candidate = 2
    while len(primes_list) < num_primes:
        is_prime = all(candidate % p != 0 for p in primes_list if p * p <= candidate)
        if is_prime:
            primes_list.append(candidate)
        candidate += 1
    return primes_list

def convert_leaves(primes_list):
    return [int.to_bytes(prime, (prime.bit_length() + 7) // 8, 'big').rjust(32, b'\x00') for prime in primes_list]

def hash_pair(a, b):
    """
        Hashes a pair of bytes32 values in sorted order to ensure consistency.
        Uses keccak_256, similar to Solidity's keccak256.
    """
    hasher = keccak.new(digest_bits=256)
    # Sort the pair to maintain consistency (Merkle trees require ordered hashing)
    hasher.update(a if a < b else b)
    hasher.update(b if a < b else a)
    return hasher.digest()


def build_merkle(leaves):
    tree = [leaves]
    while len(tree[-1]) > 1:
        layer = []
        for i in range(0, len(tree[-1]), 2):
            left = tree[-1][i]
            right = tree[-1][i + 1] if i + 1 < len(tree[-1]) else left
            layer.append(hash_pair(left, right))
        tree.append(layer)
    return tree

def prove_merkle(merkle_tree, random_indx):
    proof = []
    leaf_index = random_indx
    for layer in merkle_tree[:-1]:
        sibling_index = leaf_index ^ 1
        proof.append(layer[sibling_index])
        leaf_index //= 2
    return proof

def sign_challenge(challenge):
    acct = get_account()
    addr = acct.address
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    sig = acct.sign_message(eth_encoded_msg)
    return addr, sig.signature.hex()

def send_signed_msg(proof, random_leaf):
    chain = 'bsc'
    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)
    contract = w3.eth.contract(address=address, abi=abi)
    
    tx = contract.functions.submit(proof, random_leaf).buildTransaction({
        'from': acct.address,
        'nonce': w3.eth.getTransactionCount(acct.address),
        'gas': 200000,
        'gasPrice': w3.eth.gas_price,
    })
    signed_tx = w3.eth.account.sign_transaction(tx, acct.key)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    return w3.toHex(tx_hash)

# Helper functions that do not need to be modified remain the same
