import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import geth_poa_middleware
import math

def merkle_assignment():
    # Define the number of prime numbers needed for the Merkle tree leaves
    total_primes = 8192
    prime_numbers = generate_primes(total_primes)

    # Verification checks for correct number and last prime
    if len(prime_numbers) != total_primes:
        print(f"Error: Expected {total_primes} primes, but got {len(prime_numbers)}.")
        return
    if prime_numbers[-1] != 84017:
        print(f"Error: The 8192nd prime is {prime_numbers[-1]}, expected 84017.")
        return

    # Convert the prime list into bytes32 format
    leaf_nodes = convert_leaves(prime_numbers)

    # Connect to blockchain
    blockchain = 'bsc'
    w3 = connect_to(blockchain)
    if not w3:
        print("Error: Connection to the blockchain failed.")
        return
    contract_address, contract_abi = get_contract_info(blockchain)
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)

    # Select an unclaimed leaf node for proof
    chosen_leaf_index = select_unclaimed_leaf(w3, contract, leaf_nodes, total_primes)
    if chosen_leaf_index is None:
        print("Error: No unclaimed leaves available.")
        return

    # Build Merkle tree and generate proof
    merkle_tree = build_merkle(leaf_nodes)
    proof = prove_merkle(merkle_tree, chosen_leaf_index)

    # Sign challenge and verify
    challenge_text = ''.join(random.choice(string.ascii_letters) for _ in range(32))
    address, signature = sign_challenge(challenge_text)

    print(f"Address: {address}")
    print(f"Signature: {signature}")

    if sign_challenge_verify(challenge_text, address, signature):
        transaction_hash = send_signed_msg(w3, contract, proof, leaf_nodes[chosen_leaf_index])
        print(f"Transaction hash: {transaction_hash}")
    else:
        print("Error: Signature verification failed.")

def generate_primes(count):
    # Initialize a sieve for prime generation
    sieve_bound = 2000000
    is_prime = [True] * sieve_bound
    is_prime[0:2] = [False, False]
    primes_found = []

    # Sieve of Eratosthenes to identify prime numbers
    for number in range(2, sieve_bound):
        if is_prime[number]:
            primes_found.append(number)
            if len(primes_found) >= count:
                break
            for multiple in range(number * number, sieve_bound, number):
                is_prime[multiple] = False
    if len(primes_found) < count:
        raise ValueError("Sieve size too small to generate the required number of primes.")
    return primes_found

def convert_leaves(prime_list):
    # Convert each prime to 32-byte representation
    return [prime.to_bytes(32, 'big') for prime in prime_list]

def build_merkle(leaves):
    # Initialize tree structure with leaves as the first level
    tree_structure = [leaves]
    current_nodes = leaves

    # Iteratively hash pairs of nodes to build the tree up to the root
    while len(current_nodes) > 1:
        next_level = []
        for i in range(0, len(current_nodes), 2):
            left = current_nodes[i]
            right = current_nodes[i + 1] if i + 1 < len(current_nodes) else left
            parent_hash = hash_pair(left, right)
            next_level.append(parent_hash)
        tree_structure.append(next_level)
        current_nodes = next_level
    return tree_structure

def prove_merkle(tree, index):
    # Construct a proof of inclusion for a given leaf
    proof_path = []
    idx = index
    for level in tree[:-1]:
        sibling_idx = idx ^ 1
        if sibling_idx < len(level):
            sibling = level[sibling_idx]
        else:
            sibling = level[idx]
        proof_path.append(sibling)
        idx //= 2
    return proof_path

def select_unclaimed_leaf(w3, contract, leaves, total_leaves):
    # Attempt to select an unclaimed leaf from the Merkle tree
    for _ in range(10000):
        idx = random.randint(1, total_leaves - 1)
        leaf_prime = int.from_bytes(leaves[idx], 'big')
        try:
            owner = contract.functions.getOwnerByPrime(leaf_prime).call()
            if owner == '0x0000000000000000000000000000000000000000':
                return idx
        except Exception as e:
            print(f"Error checking owner for prime {leaf_prime}: {e}")
    return None

def sign_challenge(challenge_text):
    account = get_account()
    encoded_message = eth_account.messages.encode_defunct(text=challenge_text)
    signed_message = eth_account.Account.sign_message(encoded_message, private_key=account.key)
    return account.address, signed_message.signature.hex()

def send_signed_msg(w3, contract, proof, chosen_leaf):
    # Retrieve account and contract details, then send the signed transaction
    account = get_account()
    try:
        submit_function = contract.functions.submit
    except AttributeError:
        print("Error: 'submit' function not found in the contract ABI.")
        return '0x'

    # Build and send the transaction
    try:
        tx = submit_function(proof, chosen_leaf).build_transaction({
            'from': account.address,
            'nonce': w3.eth.get_transaction_count(account.address),
            'gas': 500000,
            'maxFeePerGas': w3.to_wei('20', 'gwei'),
            'maxPriorityFeePerGas': w3.to_wei('1', 'gwei'),
            'chainId': 97
        })
        signed_tx = w3.eth.account.sign_transaction(tx, account.key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    except Exception as e:
        print(f"Error in transaction: {e}")
        return '0x'
    return tx_hash.hex()

# Reused helper functions for connecting, hashing, etc.
def connect_to(chain):
    if chain == 'avax':
        api_url = "https://api.avax-test.network/ext/bc/C/rpc"
    elif chain == 'bsc':
        api_url = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    else:
        print(f"{chain} is not a valid option for 'connect_to()'")
        return None
    w3 = Web3(Web3.HTTPProvider(api_url))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return w3

def get_account():
    path = Path(__file__).parent.absolute().joinpath('sk.txt')
    with open(path, 'r') as f:
        sk = f.readline().strip()
    return eth_account.Account.from_key(sk[2:] if sk.startswith("0x") else sk)

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

def sign_challenge_verify(challenge, address, signature):
    message = eth_account.messages.encode_defunct(text=challenge)
    return eth_account.Account.recover_message(message, signature=signature) == address

def hash_pair(a, b):
    return Web3.solidity_keccak(['bytes32', 'bytes32'], [min(a, b), max(a, b)])

if __name__ == "__main__":
    merkle_assignment()
