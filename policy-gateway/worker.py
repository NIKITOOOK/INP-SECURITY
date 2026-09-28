"""Private stdin/stdout transport for the lab adapter. No network listener."""
import json
import sys

from engine import Engine, PolicyError, fields, load_policy

MAX_LINE = 1024 * 1024


def main():
    try:
        engine = Engine(load_policy(sys.argv[1]))
    except (PolicyError, IndexError):
        return 2
    for line in iter(lambda: sys.stdin.buffer.readline(MAX_LINE + 1), b''):
        if len(line) > MAX_LINE:
            return 2
        message_id = None
        try:
            request = json.loads(line)
            fields(request, ['id', 'method', 'params'])
            message_id = request['id']
            if type(message_id) is not int or not isinstance(request['params'], dict):
                raise PolicyError('Invalid request')
            params = request['params']
            if request['method'] == 'ping':
                fields(params, [])
                result = {'policy_digest': engine.policy_digest, 'policy_version': engine.config['policy_version']}
            elif request['method'] == 'decide':
                fields(params, ['event', 'approval_token'])
                result = engine.decide(params['event'], params['approval_token'])
            elif request['method'] == 'approve':
                fields(params, ['pending_id'])
                if not isinstance(params['pending_id'], str):
                    raise PolicyError('Invalid pending id')
                result = {'token': engine.approve(params['pending_id'])}
            else:
                raise PolicyError('Unknown method')
            response = {'id': message_id, 'result': result}
        except (ValueError, TypeError, RecursionError):
            response = {'id': message_id, 'error': 'INVALID_REQUEST'}
        sys.stdout.write(json.dumps(response, ensure_ascii=True, allow_nan=False) + '\n')
        sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
