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

import click
import ecdsa
import sha3
import yaml

import lookups
import monitoring
import targets


ETH_ADDRESS_LENGTH = 40


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
        keccak = sha3.keccak_256()
        keccak.update(pub)
        address = keccak.hexdigest()[24:]
        return priv.hexlify_private(), address


def test_get_public_address():
    sample_data = {
        '66873FDEF9BEC6F5D39D840CD7DDE4CA94270D3BF3AA9C5B372CDB5E07EADEFA': 'Dd36d7b54d489f4c2c0A7Ad57fc7180bAdD60072',
        'C45910361C0BD601F8F1D93F53882EC7989160B97B095F3F4DA46F8206455761': '5EF98356CDd925203b5aeD05045dfd81A7667619',
        }
    for private_key, eth_address in sample_data.items():
        assert (private_key.lower(), eth_address.lower()) == SigningKey.public_address(private_key)


def GetResourcePath(*path_fragments):
    """Return a path to a local resource (relative to this script)"""
    try:
        base_dir = os.path.dirname(__file__)
    except NameError:
        # __file__ is not defined in some case, use the current path
        base_dir = os.getcwd()

    return os.path.join(base_dir, 'data', *path_fragments)


def EchoLine(duration, attempts, private_key, strength, address, closest, newline=False):
    """Write a guess to the console."""
    click.secho('\r%012.6f %08x %s % 3d ' % (duration,
                                             attempts,
                                             private_key,
                                             strength),
                nl=False)
    # FIXME show matching digits not just leading digits
    click.secho(address[:strength], nl=False, bold=True)
    click.secho(address[strength:], nl=False)
    click.secho(' %- s' % closest, nl=newline)


def EchoHeader():
    """Write the names of the columns in our output to the console."""
    click.secho('%-12s %-8s %-64s %-3s %-40s %-40s' % ('duration',
                                                       'attempts',
                                                       'private-key',
                                                       'str',
                                                       'address',
                                                       'closest'))

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
@click.argument('eth_address', nargs=-1)
@click.command()
def main(fps, timeout, max_guesses, addresses, port, no_port, strategy, quiet, eth_address):
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
    fps = 1.0 / float(fps) if fps > 0 else fps
    last_frame = 0

    varz.start_time = time.asctime(time.localtime())
    start_time = time.perf_counter()

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

            if last_frame + fps < now:
                if not quiet:
                    EchoLine(now - start_time,
                             varz.num_tries,
                             private_key_hex,
                             strength,
                             address,
                             closest)
                last_frame = now

            # the current guess was as close or closer to a valid ETH address
            # show it and update our best guess counter
            if current >= varz.best_score:
                if not quiet:
                    EchoLine(now - start_time,
                             varz.num_tries,
                             private_key_hex,
                             strength,
                             address,
                             closest,
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
        pass

    varz.elapsed_time = time.perf_counter() - start_time
    click.echo('')
    click.echo('Summary')
    click.echo('-------')
    click.echo('%-20s: %s' % ('Total guesses', varz.num_tries))
    click.echo('%-20s: %s' % ('Seconds', varz.elapsed_time))
    click.echo('%-20s: %s' % ('Guess / sec', float(varz.num_tries) / varz.elapsed_time))
    click.echo('%-20s: %s' % ('Num targets', len(target_addresses)))
    click.echo('')
    click.echo('Best Guess')
    click.echo('----------')
    for key, val in sorted(varz.best_guess.items()):
        click.echo('%-20s: %s' % (key, val))
    click.echo('%-20s: %s' % ('Strength', varz.difficulty))

    httpd.Stop()


if '__main__' == __name__:
    main()
