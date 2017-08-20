import io
import json
import math
from opcodes import *
from tools import *
from binascii import hexlify, unhexlify

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_FORKID = 0x40
SIGHASH_ANYONECANPAY = 0x80


def get_stream(stream):
    if type(stream) != io.BytesIO:
        if type(stream) == str:
            stream = unhexlify(stream)
        if type(stream) == bytes:
            stream = io.BytesIO(stream)
        else:
            raise TypeError
    return stream

class Opcode():
  """ Class opcode """
  def __init__(self, raw_opcode, data, data_length = b""):
    self.raw     = raw_opcode
    if self.raw in RAW_OPCODE:
        if self.raw in (OPCODE["OP_PUSHDATA1"], OPCODE["OP_PUSHDATA2"], OPCODE["OP_PUSHDATA4"]):
            self.str = '<%s>' % len(data)
        else:
            self.str = RAW_OPCODE[self.raw]
    elif self.raw < b'L':
      self.str = '<%s>' % len(data)
    else:
      self.str = '[?]'
    self.data = data
    self.data_length = data_length

  def __str__(self):
    return self.str

  @classmethod
  def to_raw(cls, name):
    if name in OPCODE:
      return OPCODE[name]
    else:
      return b''

  @classmethod
  def pop_from_stream (cls, stream):
    b = stream.read(1)
    if not b: return None
    data = b''
    data_length = b''
    if b <= OPCODE["OP_PUSHDATA4"]:
      if b < OPCODE["OP_PUSHDATA1"]: s = int.from_bytes(b,'little')
      elif b == OPCODE["OP_PUSHDATA1"]:
        data_length = stream.read(1)
        s = int.from_bytes( data_length ,'little')
      elif b == OPCODE["OP_PUSHDATA2"]:
        data_length = stream.read(2)
        s = int.from_bytes( data_length ,'little')
      elif b == OPCODE["OP_PUSHDATA4"]:
        data_length = stream.read(4)
        s = int.from_bytes( data_length ,'little')
      data = stream.read(s)
      if len(data)!=s:
        return None
        #print(ord(b))
        #print(data)
        raise Exception('opcode read error')
    return cls(b,data,data_length)



class Script():
    """ 
    Bitcoin script class 
    """
    def __init__(self, raw_script, coinbase = False):
        self.raw = raw_script
        stream = io.BytesIO(raw_script)
        self.script = []
        self.address = list()
        self.pattern = ""
        self.asm = ""
        self.data = b''
        self.type = "NON_STANDART"
        self.ntype = 5
        self.op_sig_count = 0
        if coinbase:
            self.pattern = "<coinbase>"
            self.asm = hexlify(raw_script).decode()
            return
        while True:
            o = Opcode.pop_from_stream(stream)
            if o is None: break
            if o.raw == b'\xac' or o.raw == b'\xad':  # OP_CHECKSIG OP_CHECKSIGVERIFY
                self.op_sig_count += 1
            self.script.append(o)
            self.pattern += o.str + ' '
            if o.data:
                self.asm += hexlify(o.data).decode() + ' '
            else:
                self.asm += o.str + ' '
        self.asm = self.asm.rstrip()
        self.pattern= self.pattern.rstrip()
        # check script type
        if self.pattern == "OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG":
            self.type = "P2PKH"
            self.ntype = 0
            self.address.append(self.script[2].data)
        elif self.pattern == "OP_HASH160 <20> OP_EQUAL":
            self.type = "P2SH"
            self.ntype = 1
            self.op_sig_count = 20
            self.address.append(self.script[1].data)
        elif self.pattern == "<65> OP_CHECKSIG" or self.pattern == "<33> OP_CHECKSIG" :
            self.type = "PUBKEY"
            self.ntype = 2
            ripemd = ripemd160(hashlib.sha256(self.script[0].data).digest())
            self.address.append(ripemd)
        elif len(self.script) == 2:
            if self.script[0].raw == b'j': # OP_RETURN
                if self.script[1].raw < b'Q': # <0 to 80 bytes of data>
                    self.data = self.script[1].data
                    self.type = "NULL_DATA"
                    self.ntype = 3
        elif len(self.script)>= 4:
            if self.script[-1].raw == b'\xae' and self.script[-2].raw <= b'`' and self.script[-2].raw >= b'Q' : #  OP_CHECKMULTISIG   "OP_1"  "OP_16"
                if self.script[0].raw <= b'`' and self.script[0].raw >= b'Q':
                    self.vbare_multisig_accepted = ord(self.script[0].raw) - 80
                    self.bare_multisig_from = ord(self.script[-2].raw) - 80
                    self.type = "MULTISIG"
                    self.ntype = 4
                    for o in self.script[1:-2]:
                        # if o.str != '<65>' and o.str != '<33>':
                        # 0F20C8DAB4A8DFB50DD5CF4C276BA1FAB1C79CAE5B6641BE2F67FAACA838C1E6
                        # в данной транзакции 66 байт на ключ он некоректен но
                        # это не мешает тратить деньги используя другие ключи
                        #     self.type = "NON_STANDART"
                        #     break
                        self.op_sig_count += 1
                        ripemd = ripemd160(hashlib.sha256(o.data).digest())
                        self.address.append(ripemd)
                        # p2sh address inside multisig?




class Input:
    """ Transaction Input class """
    #  outpoint = (b'00f0f09...',n')
    #  script   = raw bytes
    #  sequense = int
    def __init__(self, outpoint, script, sequence):
        self.outpoint = outpoint
        self.sequence = sequence
        self.pk_script = None
        self.amount = None
        self.p2sh_type = None
        self.coinbase = False
        if outpoint == (b'\x00'*32 ,0xffffffff): self.coinbase = True
        self.sig_script = Script(script, self.coinbase)
        self.double_spend = None
        self.lock = False
        self.addresses = []
        self.reedomscript = None
        if len(self.sig_script.script) > 0:
            try:
                if len(self.sig_script.script[-1].data) <= 520:
                    self.reedomscript = Script(self.sig_script.script[-1].data)
                else:
                    pass
            except Exception as err:
                pass

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        outpoint = stream.read(32), int.from_bytes(stream.read(4), 'little')
        script_len = from_var_int(read_var_int(stream))
        script = stream.read(script_len)
        sequence = int.from_bytes(stream.read(4), 'little')

        return cls(outpoint, script, sequence)

class Output:
    """ Transactin output class """
    def __init__(self, value, script):
        self.value = value
        self.pk_script = Script(script)

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        value = int.from_bytes(stream.read(8), 'little')
        script_len = from_var_int(read_var_int(stream))
        pk_script = stream.read(script_len)
        return cls(value, pk_script)

class Witness:
    def __init__(self, data, empty = False):
        self.empty = empty
        self.witness = data

    def __str__(self):
        return json.dumps([binascii.hexlify(w).decode() for w in self.witness])

    def hex(self):
        return [binascii.hexlify(w).decode() for w in self.witness]

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        empty = False
        witness_len = from_var_int(read_var_int(stream))
        witness = []
        for i in range(witness_len):
            l = from_var_int(read_var_int(stream))
            w = stream.read(l)
            witness.append(w)
            if w == b'\x00' and witness_len == 1:
                empty = True
        return cls(witness, empty)




class Transaction():
    def __init__(self, version, tx_in, tx_out, lock_time,
                 hash=None, size = 0, timestamp = None,
                 marker = None, flag = None, witness = None,
                 whash = None, vsize = None):
        self.hash = hash
        self.whash = whash
        self.vsize = vsize
        self.witness = witness
        self.marker = marker
        self.flag = flag
        self.valid = True
        self.lock = False
        self.orphaned = False
        self.in_sum = None
        self.tx_fee = None
        self.version = version
        self.tx_in_count = len(tx_in)
        self.tx_in = tx_in
        self.tx_out_count = len (tx_out)
        self.tx_out = tx_out
        self.lock_time = lock_time
        self.coinbase = self.tx_in[0].coinbase
        self.double_spend = 0
        self.data = None
        self.ip = None
        self.size = size
        if timestamp is not None : self.timestamp = timestamp
        else: self.timestamp = int(time.time())
        self.op_sig_count = 0
        self.sum_value_age = 0
        self.total_outs_value = 0
        for i in self.tx_out:
            self.op_sig_count += i.pk_script.op_sig_count
            if i.pk_script.type=="NULL_DATA":
                self.data = i.pk_script.data
        for out in self.tx_out:
            self.total_outs_value += out.value


    def __str__(self):
        return 'Transaction object [%s] [%s]'% (hexlify(self.hash[::-1]),id(self))


    def serialize(self, sighash_type = 0, input_index = -1, subscript = b''):
        if self.tx_in_count-1 < input_index  : raise Exception('Input not exist')
        if ((sighash_type&31) == SIGHASH_SINGLE) and (input_index>(len(self.tx_out)-1)): return b'\x01'+b'\x00'*31
        version = self.version.to_bytes(4,'little')
        ninputs = b'\x01' if sighash_type &  SIGHASH_ANYONECANPAY else to_var_int(self.tx_in_count)
        inputs = []
        for number, i in enumerate(self.tx_in):
            if (sighash_type &  SIGHASH_ANYONECANPAY) and (input_index != number): continue
            input = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
            if sighash_type == 0 or input_index == number:
                input += ((to_var_int(len(subscript)) + subscript) if sighash_type else \
                (to_var_int(len(i.sig_script.raw)) + i.sig_script.raw)) + i.sequence.to_bytes(4,'little')
            else:
                input += b'\x00' + (i.sequence.to_bytes(4,'little') if \
                ((sighash_type&31) == SIGHASH_ALL) else b'\x00\x00\x00\x00')
            inputs.append(input)
        nouts = b'\x00' if (sighash_type&31) == SIGHASH_NONE else ( to_var_int(input_index + 1) if \
            (sighash_type&31) == SIGHASH_SINGLE else to_var_int(self.tx_out_count))
        outputs = []
        if  (sighash_type&31) != SIGHASH_NONE:
            for number, i in enumerate(self.tx_out):
                if number > input_index and (sighash_type&31) == SIGHASH_SINGLE: continue
                outputs.append(b'\xff'*8+b'\x00' if (sighash_type&31) == SIGHASH_SINGLE and (input_index != number)\
                else i.value.to_bytes(8,'little')+to_var_int(len(i.pk_script.raw))+i.pk_script.raw)
        return version+ninputs+b''.join(inputs)+nouts+b''.join(outputs)+self.lock_time.to_bytes(4,'little')

    def json(self):
        r = dict()
        r["txid"] = rh2s(self.hash)
        r["wtxid"] = r["txid"] if self.whash is None else rh2s(self.whash)
        r["size"] = self.size
        r["vsize"] = self.vsize
        r["version"] = self.version
        r["locktime"] = self.lock_time
        r["vin"] = list()
        r["vout"] = list()
        for i in self.tx_in:
            input = {"txid": rh2s(i.outpoint[0]),
                     "vout": i.outpoint[1],
                     "scriptSig": {"hex": hexlify(i.sig_script.raw).decode(),
                                   "asm": i.sig_script.asm},
                     "sequence": i.sequence}
            if i.coinbase:
                input["coinbase"] = hexlify(i.sig_script.raw).decode()
            r["vin"].append(input)
        if self.witness is not None:
            for index, w in enumerate(self.witness):
                r["vin"][index]["txinwitness"] = w.hex()
        for index, o in enumerate(self.tx_out):
            out = {"value": o.value,
                   "n": index,
                   "scriptPubKey": {"hex": hexlify(o.pk_script.raw).decode()},
                                    "asm": o.pk_script.asm,
                                    "type": o.pk_script.type}
            r["vout"].append(out)

        return json.dumps(r)


    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        raw_tx = bytearray()
        raw_wtx = bytearray()
        start = stream.tell()
        version = int.from_bytes(stream.read(4), 'little')
        marker = stream.read(1)
        flag =  stream.read(1)
        if marker == b"\x00" and flag ==  b"\x01":
            # segwit format
            point1 = stream.tell()
            tx_in = read_var_list(stream, Input)
            tx_out = read_var_list(stream, Output)
            point2 = stream.tell()
            inputs_count = len(tx_in)
            witness = [Witness.deserialize(stream) for i in range(inputs_count)]
            point3 = stream.tell()
            lock_time = int.from_bytes(stream.read(4), 'little')
            # calculate tx_id hash
            size = stream.tell() - start
            stream.seek(start)
            raw_tx += stream.read(4)
            stream.seek(2,1)
            raw_tx += stream.read(point2 - point1)
            stream.seek(point3-point2, 1)
            raw_tx += stream.read(4)

            tx_id = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
            for w in witness:
                if not w.empty:
                    # caluculate wtx_id
                    stream.seek(start)
                    data = stream.read(size)
                    wtx_id = hashlib.sha256(hashlib.sha256(data).digest()).digest()
                    break
                else:
                    wtx_id = tx_id
            vsize = math.ceil((len(raw_tx) * 3 + size) / 4)
        else:
            stream.seek(start)
            marker = None
            flag = None
            version = int.from_bytes(stream.read(4), 'little')
            tx_in = read_var_list(stream, Input)
            tx_out = read_var_list(stream, Output)
            witness = None
            lock_time = int.from_bytes(stream.read(4), 'little')
            size = stream.tell() - start
            stream.seek(start)
            data = stream.read(size)
            tx_id = hashlib.sha256(hashlib.sha256(data).digest()).digest()
            wtx_id = None
            vsize = size

        return cls(version, tx_in, tx_out, lock_time,
                   hash = tx_id, size = size,
                   marker = marker, flag = flag,
                   witness = witness, whash = wtx_id, vsize = vsize)


class Block():
    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, txs, block_size,hash=None):
        self.hash = hash
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.txs = txs
        self.block_size = block_size
        self.height = None
        self.id = None
        self.chain = None
        self.amount = 0
        self.mountpoint = None
        self.side_branch_set = None
        self.tx_hash_list = list()
        self.op_sig_count = 0
        for t in txs:
            if t.hash in txs:
                raise Exception("CVE-2012-2459") # merkle tree malleability
            self.op_sig_count += t.op_sig_count
            self.tx_hash_list.append(t.hash)
        self.target = None
        self.fee = 0

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        header = stream.read(80)
        stream.seek(-80, 1)
        kwargs = {
            'hash': hashlib.sha256(hashlib.sha256(header).digest()).digest(),
            'version': int.from_bytes(stream.read(4), 'little'),
            'prev_block': stream.read(32),
            'merkle_root': stream.read(32),
            'timestamp': int.from_bytes(stream.read(4), 'little'),
            'bits': int.from_bytes(stream.read(4), 'little'),
            'nonce': int.from_bytes(stream.read(4), 'little'),
            'txs': read_var_list(stream, Transaction),
            'block_size': stream.tell()
        }
        return cls(**kwargs)

