#!/usr/bin/python3

'''
nagios/icinga plugin to check bgp peer status
'''

# this module contains mixins, disabling public method check
# pylint: disable=too-few-public-methods
# override argparse options title, to avoid confusion about optional
# arguments
# pylint: disable=protected-access
# There is one broad except around the main function, to have a proper
# exit/error code showing up in icing
# pylint: disable=broad-except

__author__ = 'Andre Keller <andre.keller@vshn.ch>'
__copyright__ = 'Copyright (c) 2015, VSHN AG, andre.keller@vshn.ch'
__license__ = 'BSD'
__version__ = '0.1.0'

from simple_icinga_plugin import ArgParser, PluginError, \
        exit_critical, exit_ok, exit_unknown, exit_warning
import tikapy
import ipaddress
import logging

class BgpMixin():
    '''API client Mixin providing methods to query bgp information'''
    def get_peer_details(self, peer):
        '''Get peer details by its remote address.
        Args:
          - peer: Remote-Address (IPv4 or IPv6 address) or name of peer
        Raises:
          PluginError - If no peer is configured or if API reply is bogus.
        Returns:
          dict containing bgp peer details
        '''
        try:
            peer = ipaddress.ip_address(peer)
            query_filter = '?remote-address=%s' % peer
        except ValueError:
            query_filter = '?name=%s' % peer
        result = self.talk([
            '/routing/bgp/peer/getall',
            query_filter,
        ])
        if not result:
            raise PluginError("Peer '%s' not configured" % peer)
        if len(result) > 1:
            raise PluginError(
                'API returned more than one record, cannot handle this'
            )
        try:
            _, peer_details = result.popitem()
        except (AttributeError, TypeError):
            raise PluginError(
                'API did not return dict, cannot handle this'
            )
        return peer_details

class ApiClient(BgpMixin, tikapy.TikapyClient):
    '''ApiClient with BGP query support'''
    pass

class SslApiClient(BgpMixin, tikapy.TikapySslClient):
    '''SSL ApiClient with BGP query support'''
    pass

def parse_args():
    '''parse command line arguments

    Returns: simple_icinga_plugin.ArgParser object

    Raises:
      PluginError - If arguement parsing fails
    '''
    parser = ArgParser('Check Miktrotik RouterOS bgp peer status')
    parser._optionals.title = 'options'
    parser.add_argument(
        '-d', '--debug', action='store_true', default=False,
        help='Enable and print API debugging information'
    )
    parser.add_argument(
        '-H', '--host', type=str, required=True,
        help='IPv4/IPv6 address of API endpoint'
    )
    parser.add_argument(
        '-P', '--port', type=int,
        help='API port (defaults to 8728 (plaintext), 8729 (ssl))'
    )
    parser.add_argument(
        '-s', '--ssl', action='store_true', default=False,
        help='Use SSL to connect to API'
    )
    parser.add_argument(
        '-u', '--user', type=str, required=True,
        help='User for API authentication'
    )
    parser.add_argument(
        '-p', '--password', type=str, required=True,
        help='Password for API authentication'
    )
    parser.add_argument(
        'peer', type=str,
        help='IPv4/IPv6 remote-address or name of bgp peer'
    )
    return parser.parse_args()

def get_peer_details(args):
    '''get peer details from Tikapy

    Args:
      - args: ArgumentParser object with host, port, user and password
              attributes.

    Returns: dict with peer details
    '''
    # establish connection to socket and login user
    api_client_args = {'address': args.host}
    if args.port:
        api_client_args['port'] = args.port
    if args.ssl:
        client = SslApiClient(**api_client_args)
    else:
        client = ApiClient(**api_client_args)
    client.login(args.user, args.password)

    # get bgp peer details from API
    return client.get_peer_details(args.peer)

def main():
    '''main function'''
    # parse command line arguments
    try:
        args = parse_args()
    except PluginError as exc:
        exit_unknown('%s' % exc)

    # setup logging for tikapy
    api_logger = logging.getLogger('tikapy')
    if args.debug:
        api_logger.setLevel(logging.DEBUG)
        api_logger_handler = logging.StreamHandler()
        api_logger_formatter = logging.Formatter(
            'API: %(levelname)s: %(message)s'
        )
        api_logger_handler.setFormatter(api_logger_formatter)
        api_logger.addHandler(api_logger_handler)
    else:
        api_logger.addHandler(logging.NullHandler())

    # get bgp peer details
    try:
        peer_details = get_peer_details(args)
    except tikapy.ClientError as exc:
        exit_unknown('API error: {exc}', exc=exc)
    except PluginError as exc:
        exit_unknown('{exc}', exc=exc)

    # process bgp peer details
    try:
        if not peer_details['state'] == 'established':
            exit_critical(
                'Session to {remote} ({remoteas}) in {state} state',
                remote=peer_details['remote-address'],
                remoteas=peer_details['remote-as'],
                state=peer_details['state']
            )
        exit_ok(
            'Session to {remote} ({remoteas}) established for {uptime}',
            remote=peer_details['remote-address'],
            remoteas=peer_details['remote-as'],
            uptime=peer_details['uptime']
        )
    except KeyError as exc:
        if peer_details.get('disabled', False):
            exit_warning(
                'Session to {remote} (AS{remoteas}) disabled',
                remote=peer_details['remote-address'],
                remoteas=peer_details['remote-as']
            )
        exit_unknown('Could not parse peer details: {exc}', exc=exc)

if __name__ == '__main__':
    try:
        # call main function
        main()
    except Exception as exc:
        exit_unknown('Unhandled error occured: %s' % exc)
