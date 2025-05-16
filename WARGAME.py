#!/usr/bin/env python3
"""Brute force well-known ETH addresses, WarGames-style.

Warning: this is utterly futile.  I've only done this to get a feel
for how secure private keys are against brute-force attacks.
"""

import codecs
import os
import sys
import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor

import click
import ecdsa
import hashlib
import yaml
import requests

import lookups
import monitoring
import targets


ETH_ADDRESS_LENGTH = 40
BALANCE_WORKER_COUNT = 8  # Number of balance checking threads


def calc_strength(guess, target) -> int:
    """Calculate the strength of an address guess"""
    strength = 0
    for lhs, rhs in zip(guess, target):
        strength += 1 if lhs == rhs else 0
    return strength


class SigningKey(ecdsa.SigningKey):

    @staticmethod
    def _hexlify(val):
        return codecs.encode(val, 'hex').decode('utf-8')

    def hexlify_private(self):
        return self._hexlify(self.to_string())

    def hexlify_public(self):
        return self._hexlify(self.get_verifying_key().to_string())

    @staticmethod
    def public_address(private_key_str=None):
        if private_key_str is not None:
            import binascii
            _p = private_key_str.lower()
            _p = bytes(_p, 'utf-8')
            _p = binascii.unhexlify(_p)
            priv = SigningKey.from_string(_p, curve=ecdsa.SECP256k1)
        else:
            priv = SigningKey.generate(curve=ecdsa.SECP256k1)

        pub = priv.get_verifying_key().to_string()
        keccak = hashlib.sha3_256()
        keccak.update(pub)
        address = keccak.hexdigest()[24:]
        return priv.hexlify_private(), address


def GetResourcePath(*path_fragments):
    """Return a path to a local resource (relative to this script)"""
    try:
        base_dir = os.path.dirname(__file__)
    except NameError:
        # __file__ is not defined in some case, use the current path
        base_dir = os.getcwd()

    return os.path.join(base_dir, 'data', *path_fragments)


def EchoLine(duration, attempts, private_key, strength, address, closest, balance, newline=False):
    """Write a guess to the console."""
    click.secho('\r%012.6f %08x %s % 3d ' % (duration,
                                             attempts,
                                             private_key,
                                             strength),
                nl=False)
    # Show matching digits not just leading digits
    click.secho(address[:strength], nl=False, bold=True)
    click.secho(address[strength:], nl=False)
    click.secho(' %-40s' % closest, nl=False)
    click.secho(' %12.6f ETH' % balance, nl=newline)


def EchoHeader():
    """Write the names of the columns in our output to the console."""
    click.secho('%-12s %-8s %-64s %-3s %-40s %-40s %s' % ('duration',
                                                          'attempts',
                                                          'private-key',
                                                          'str',
                                                          'address',
                                                          'closest',
                                                          'balance (ETH)'))


def fetch_balance(address, api_key):
    """Fetch ETH balance in Ether using Etherscan API, returns float."""
    try:
        url = f'https://api.etherscan.io/api?module=account&action=balance&address=0x{address}&tag=latest&apikey={api_key}'
        response = requests.get(url, timeout=10)
        data = response.json()
        if data['status'] == '1' and 'result' in data:
            wei_balance = int(data['result'])
            eth_balance = wei_balance / 1e18
            return eth_balance
        else:
            return 0.0
    except Exception:
        return 0.0


def balance_worker(api_key, address_queue, balances_found, total_balance_lock, total_balance, stop_event):
    while not stop_event.is_set() or not address_queue.empty():
        try:
            eth_addr, priv_key = address_queue.get(timeout=0.1)
        except queue.Empty:
            continue
        balance = fetch_balance(eth_addr, api_key)
        balances_found[eth_addr] = (priv_key, balance)
        with total_balance_lock:
            total_balance[0] += balance
        address_queue.task_done()


@click.option('--fps',
              default=60,
              help='Use this many frames per second when showing guesses.  '
                   'Use non-positive number to go as fast as possible.')
@click.option('--timeout',
              default=-1,
              help='If set to a positive integer, stop trying after this many '
                   'seconds.')
@click.option('--max-guesses',
              default=0,
              help='If set to a positive integer, stop trying  after this many '
                   'attempts.')
@click.option('--addresses',
              type=click.File('r'),
              default=GetResourcePath('addresses.yaml'),
              help='Filename for yaml file containing target addresses.')
@click.option('--port',
              default=8120,
              help='Monitoring port for runtime metrics.')
@click.option('--no-port',
              is_flag=True,
              default=False,
              help='Disable monitoring port.')
@click.option('--strategy',
              type=click.Choice(['trie', 'nearest', 'bisect'], case_sensitive=False),
              default='nearest',
              help='Choose a lookup strategy for eth addresses')
@click.option('--quiet',
              default=False,
              is_flag=True,
              help='Skip the animation')
@click.option('--apikeyfile',
              type=click.Path(exists=True, dir_okay=False),
              default=GetResourcePath('etherscan_api_key.txt'),
              help='File containing your Etherscan API key.')
@click.option('--output',
              type=click.Path(dir_okay=False, writable=True),
              default='found_addresses.txt',
              help='File to output found addresses with balances.')
@click.argument('eth_address', nargs=-1)
@click.command()
def main(fps, timeout, max_guesses, addresses, port, no_port, strategy, quiet, apikeyfile, output, eth_address):
    # Load Etherscan API key
    try:
        with open(apikeyfile, 'r') as f:
            api_key = f.read().strip()
    except Exception as e:
        click.echo(f"Failed to read API key file: {e}", err=True)
        sys.exit(1)

    if eth_address:
        click.echo('Attacking specific ETH addresses: ', nl=False)
        addresses = [address.lower() for address in eth_address]
    else:
        click.echo('Loading known public ETH addresses: ', nl=False)

    strategy_ctor = lookups.PickStrategy(strategy)
    start_of_load = time.perf_counter()
    target_addresses = strategy_ctor(targets.targets(addresses))
    load_time = time.perf_counter() - start_of_load
    click.echo('%d addresses read in %-3.2f seconds.' % (len(target_addresses), load_time))
    click.echo('Using "%s" strategy, consuming %s bytes (%-8.5f bytes/address).' % (
        strategy_ctor.__name__,
        target_addresses.sizeof(),
        len(target_addresses) / float(target_addresses.sizeof())))
    click.echo('')

    httpd = monitoring.Server()
    varz = httpd.Start('', 0 if no_port else port)

    varz.fps = fps
    varz.timeout = timeout if timeout > 0 else 'forever'

    # score is tuple of number of matching leading hex digits and that
    # portion of the resulting public key: (count, address[:count])
    varz.best_score = (0, '')
    varz.difficulty = httpd.DefineComputedStat(
        lambda m:
            '%d of %d digits (%3.2f%%)' % (
                 m.best_score[0],
                 ETH_ADDRESS_LENGTH,
                 100.0 * m.best_score[0] / ETH_ADDRESS_LENGTH)
    )

    # count the number of private keys generated
    varz.num_tries = 0
    varz.guess_rate = httpd.DefineComputedStat(
        lambda m:
             float(m.num_tries) / m.elapsed_time, units='guesses/sec'
    )

    # calculate the fps
    fps_interval = 1.0 / float(fps) if fps > 0 else 0
    last_frame = 0

    varz.start_time = time.asctime(time.localtime())
    start_time = time.perf_counter()

    # Queue for balance checking
    address_queue = queue.Queue()
    balances_found = {}
    total_balance = [0.0]
    total_balance_lock = threading.Lock()
    stop_event = threading.Event()

    if not quiet:
        EchoHeader()

    try:
        while varz.best_score[0] < ETH_ADDRESS_LENGTH:
            now = time.perf_counter()
            varz.elapsed_time = now - start_time
            if (timeout > 0) and (start_time + timeout < now):
                break
            if (max_guesses) and (varz.num_tries >= max_guesses):
                break

            varz.num_tries += 1

            # calculate a public eth address from a random private key
            private_key_hex, address = SigningKey.public_address()
            current = target_addresses.FindClosestMatch(address)
            strength, _, closest = current

            # Add this address for balance checking
            address_queue.put((address, private_key_hex))

            if last_frame + fps_interval < now:
                if not quiet:
                    # Show balance if already fetched, else 0
                    balance = balances_found.get(address, (None, 0.0))[1]
                    EchoLine(now - start_time,
                             varz.num_tries,
                             private_key_hex,
                             strength,
                             address,
                             closest,
                             balance)
                last_frame = now

            if current >= varz.best_score:
                if not quiet:
                    balance = balances_found.get(address, (None, 0.0))[1]
                    EchoLine(now - start_time,
                             varz.num_tries,
                             private_key_hex,
                             strength,
                             address,
                             closest,
                             balance,
                             newline=True)
                varz.best_score = current

                best_guess_report = {
                    'private-key': private_key_hex,
                    'address': address,
                }
                if closest is not None:
                    best_guess_report['closest'] = 'https://etherscan.io/address/0x%s' % (closest,)
                varz.best_guess = best_guess_report

    except KeyboardInterrupt:
        click.echo('\nGraceful shutdown initiated. Stopping address generation...')
        stop_event.set()

    # Start balance checking threads to finish checking remaining addresses
    click.echo('Waiting for balance checks to finish...')

    with ThreadPoolExecutor(max_workers=BALANCE_WORKER_COUNT) as executor:
        futures = []
        for _ in range(BALANCE_WORKER_COUNT):
            futures.append(executor.submit(balance_worker,
                                           api_key,
                                           address_queue,
                                           balances_found,
                                           total_balance_lock,
                                           total_balance,
                                           stop_event))

        # Progress display while waiting for balance checks
        while any(future.running() for future in futures):
            checked = len(balances_found)
            total = varz.num_tries
            percent = (checked / total) * 100 if total else 100
            bar_len = 40
            filled_len = int(bar_len * percent / 100)
            bar = '=' * filled_len + ' ' * (bar_len - filled_len)
            click.echo(f'\rBalance checking: [{bar}] {percent:6.2f}% ({checked}/{total})', nl=False)
            time.sleep(0.5)
        click.echo('\rBalance checking: [{}] 100.00% ({}/{})'.format('='*40, len(balances_found), varz.num_tries))

    # Write addresses with balances > 0 to output file
    with open(output, 'w') as out_file:
        for addr, (priv_key, balance) in balances_found.items():
            if balance > 0.0:
                out_file.write(f'{addr} {priv_key} {balance:.6f} ETH\n')

    varz.elapsed_time = time.perf_counter() - start_time
    click.echo('')
    click.echo('Summary')
    click.echo('-------')
    click.echo(f'Total ETH balance found: {total_balance[0]:.6f} ETH')
    click.echo('%-20s: %s' % ('Total guesses', varz.num_tries))
    click.echo('%-20s: %s' % ('Seconds', varz.elapsed_time))
    click.echo('%-20s: %s' % ('Guess / sec', float(varz.num_tries) / varz.elapsed_time))
    click.echo('%-20s: %s' % ('Num targets', len(target_addresses)))
    click.echo('')
    click.echo('Best Guess')
    click.echo('----------')
    for key, val in sorted(varz.best_guess.items()):
        click.echo('%-20s: %s' % (key, val))

    httpd.Stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
