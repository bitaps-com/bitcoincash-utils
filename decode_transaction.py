import bitcoin
import requests
import sys
from blockchain import *
import argparse




def fmt(g,n):
    return format(g/10 ** n,'0.%sf' % n).rstrip('0').rstrip('.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Bitcoin cash utils v 1.0")
    parser.add_argument("--hex", help="hex encoded transaction", type=str, metavar=('ID'))


    args = parser.parse_args()

    if not args.hex:
        print("\nError:  no hex encoded transaction provided")
        sys.exit(0)

    tx = Transaction.deserialize(args.hex)
    print("Json decoded transaction: \n")
    print(json.dumps(json.loads(tx.json()), indent=4))

