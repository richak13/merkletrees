import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import geth_poa_middleware
from Crypto.Hash import keccak
from hexbytes import HexBytes

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

def build_merkle(leaves):
    tree = [leaves]
    while len(tree[-1]) > 1:
        layer = []
        for i in range(0, len(tree[-1]), 2):
            left = tree[-1][i]
            right = tree[-1][i + 1] if i + 1 < len(tree[-1]) else left
            layer.append(hash_pair(left, right))
        tree.append(layer)
    
    # Convert root to HexBytes format
    tree[-1][0] = HexBytes(tree[-1][0])
    return tree

def prove_merkle(merkle_tree, random_indx):
    """
    Generates a Merkle proof for the leaf at `random_indx` in the Merkle Tree.
    The proof is a list of sibling nodes required to reconstruct the path to the root.
    """
    proof = []
    leaf_index = random_indx
    
    for layer in merkle_tree[:-1]:  # Skip the root layer
        sibling_index = leaf_index ^ 1  # XOR with 1 to get the sibling index
        if sibling_index < len(layer):
            proof.append(layer[sibling_index])
        leaf_index //= 2  # Move up to the next level
    
    return proof

def prove_merkle(merkle_tree, leaf_index):
    proof = []
    index = leaf_index
    for layer in merkle_tree[:-1]:  # Exclude the root layer
        if index % 2 == 0:
            sibling_index = index + 1 if index + 1 < len(layer) else index
        else:
            sibling_index = index - 1
        
        # Append the sibling to the proof
        proof.append(layer[sibling_index])
        
        # Move up to the next level in the tree
        index //= 2
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
    
    # Ensure random_leaf is in bytes32 format (32 bytes)
    if isinstance(random_leaf, int):
        leaf_bytes = random_leaf.to_bytes(32, byteorder='big')
    elif isinstance(random_leaf, bytes):
        leaf_bytes = random_leaf.rjust(32, b'\x00')
    else:
        raise TypeError("random_leaf must be an integer or bytes")

    # Ensure each item in the proof is in bytes32 format
    proof_bytes = []
    for item in proof:
        if isinstance(item, int):
            proof_bytes.append(item.to_bytes(32, byteorder='big'))
        elif isinstance(item, bytes):
            proof_bytes.append(item.rjust(32, b'\x00'))
        else:
            raise TypeError("Each proof item must be an integer or bytes")
    
    # Encode ABI for the submit function with proof and leaf arguments
    tx_data = contract.encodeABI(fn_name="submit", args=[proof_bytes, leaf_bytes])
    transaction = {
        'to': address,
        'from': acct.address,
        'data': tx_data,
        'gas': 200000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(acct.address),
    }
    
    # Sign and send the transaction
    signed_tx = w3.eth.account.sign_transaction(transaction, acct.key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    
    return tx_hash.hex()

# Helper functions that do not need to be modified
def connect_to(chain):
    if chain not in ['avax', 'bsc']:
        print(f"{chain} is not a valid option for 'connect_to()'")
        return None
    if chain == 'avax':
        api_url = "https://api.avax-test.network/ext/bc/C/rpc"
    else:
        api_url = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    w3 = Web3(Web3.HTTPProvider(api_url))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return w3

def get_account():
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath('sk.txt'), 'r') as f:
        sk = f.readline().rstrip()
    if sk[0:2] == "0x":
        sk = sk[2:]
    return eth_account.Account.from_key(sk)

def get_contract_info(chain):
    """
    Returns a contract address and contract ABI from "contract_info.json"
    for the given chain.
    """
    # Update path as necessary
    cur_dir = Path("/home/codio/workspace/")
    with open(cur_dir.joinpath("contract_info.json"), "r") as f:
        d = json.load(f)
        d = d[chain]
    return d['address'], d['abi']

def sign_challenge_verify(challenge, addr, sig):
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == addr:
        print(f"Success: signed the challenge {challenge} using address {addr}!")
        return True
    else:
        print("Failure: The signature does not verify!")
        return False

def hash_pair(a, b):
    """
    Hashes a pair of bytes32 values in sorted order to ensure consistency.
    Uses keccak_256, similar to Solidity's keccak256.
    """
    hasher = keccak.new(digest_bits=256)
    if a < b:
        hasher.update(a)
        hasher.update(b)
    else:
        hasher.update(b)
        hasher.update(a)
    return hasher.digest()

if __name__ == "__main__":
    merkle_assignment()
