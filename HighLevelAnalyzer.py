# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    """BM13xx High Level Analyzer."""

    bm_family = ChoicesSetting(['BM138x', 'BM139x'])

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'set_chipadd': {
            'format': 'Set Address chip@{{data.chipadd}} CRC={{data.crc5}}'
        },
        'write_register': {
            'format': 'Write Register chip@{{data.chipadd}} reg@{{data.regadd}}={{data.regval}} CRC={{data.crc5}}'
        },
        'chain_inactive': {
            'format': 'Chain Inactive CRC={{data.crc5}}'
        },
        'read_register': {
            'format': 'Read Register chip@{{data.chipadd}} reg@{{data.regadd}} CRC={{data.crc5}}'
        },
        # old commands
        'set_pll_divider_1': {
            'format': 'Set PLL Divider1 FBDIV: {{data.fbdiv}} REFDIV: {{data.refdiv}} CRC={{data.crc5}}'
        },
        'set_pll_divider_2': {
            'format': 'Set PLL Divider 2 POSTDIV1: {{data.postdiv1}} POSTDIV2: {{data.postdiv2}} CRC={{data.crc5}}'
        },
        'set_baud_ops': {
            'format': 'Set Baud OPS chip@{{data.chipadd}} CRC={{data.crc5}}'
        },
        'unknown': {
            'format': 'command: {{data.command}}'
        }
    }

    def __init__(self):
        # current byte position
        self._byte_pos: int = 0
        self._start_of_frame = None
        # current frame type : VIL or FIL
        self._frame_type: str = ""
        self._vil_offset:int = 0
        # current frame length : 4 for FIL, given for VIL
        self._frame_len: int = 99
        # current frame all
        self._all: str = ""
        # current frame command
        self._cmd: int = 99
        self._command: str = ""
        # datas
        self._chipadd: int = 0
        self._regadd: int = 0
        self._regval: int = 0
        self._fbdiv: int = 0
        self._refdiv: int = 0
        self._postdiv1: int = 0
        self._postdiv2: int = 0

    def decode(self, frame: AnalyzerFrame):
        if 'error' in frame.data:
            return
        raw = frame.data['data'][0]
        preamble_offset = 0
        if self.bm_family == "BM139x":
            preamble_offset += 2
        if self._byte_pos == 0:
            self._command = ""
            self._start_of_frame = frame.start_time
        if self._byte_pos == 0 + preamble_offset:
            input_length_type = (raw >> 5) & 0b111
            if input_length_type == 2:
                # VIL
                self._vil_offset = 1
                self._frame_type = "VIL"
                if (raw >> 4) & 0b1 == 0b1 :
                    self._all = "ALL"
                else:
                    self._all = "ONE"
            elif input_length_type == 1:
                # VIL
                self._vil_offset = 1
                self._frame_type = "VIL"
                self._all = "WORK"
            else:
                # FIL
                self._vil_offset = 0
                self._frame_type = "FIL"
                if (raw >> 7) & 0b1 == 0b1 :
                    self._all = "ALL"
                else:
                    self._all = "ONE"
                self._frame_len = 4
            self._cmd = raw & 0b1111
            if self.bm_family == "BM138x":
                if self._cmd == 1:
                    self._command = "set_chipadd"
                elif self._cmd == 2:
                    self._command = "set_pll_divider_2"
                elif self._cmd == 4:
                    # 'getstatus' in BM1385 Datasheet
                    self._command = "read_register"
                elif self._cmd == 5:
                    self._command = "chain_inactive"
                elif self._cmd == 6:
                    self._command = "set_baud_ops"
                elif self._cmd == 7:
                    self._command = "set_pll_divider_1"
                    self._fbdiv = 0
                    self._refdiv = 0
                elif self._cmd == 8:
                    # 'setconfig' in BM1385 Datasheet
                    self._command = "write_register"
                else:
                    self._command = "unknown"
            elif self.bm_family == "BM139x":
                if self._cmd == 0:
                    self._command = "set_chipadd"
                elif self._cmd == 1:
                    if self._all == "WORK":
                        self._command = "work"
                    else:
                        self._command = "write_register"
                elif self._cmd == 2:
                    self._command = "read_register"
                elif self._cmd == 3:
                    self._command = "chain_inactive"
                else:
                    self._command = "unknown"
        if self._byte_pos == (1 + preamble_offset) and self._frame_type == "VIL":
            # VIL
            self._frame_len = raw
        if self._command == "set_chipadd":
            if self._byte_pos == (1 + preamble_offset + self._vil_offset):
                print(self._byte_pos,preamble_offset,self._vil_offset)
                self._chipadd = raw
        elif self._command == "read_register":
            if self._byte_pos == 1 + preamble_offset + self._vil_offset:
                self._chipadd = raw
            elif self._byte_pos == 2 + preamble_offset + self._vil_offset:
                self._regadd = raw
        elif self._command == "write_register":
            if self._byte_pos == 1 + preamble_offset + self._vil_offset:
                self._chipadd = raw
            elif self._byte_pos == 2 + preamble_offset + self._vil_offset:
                self._regadd = raw
            elif self._byte_pos == 3 + preamble_offset + self._vil_offset:
                self._regval = (raw << 24)
            elif self._byte_pos == 4 + preamble_offset + self._vil_offset:
                self._regval += (raw << 16)
            elif self._byte_pos == 5 + preamble_offset + self._vil_offset:
                self._regval += (raw << 8)
            elif self._byte_pos == 6 + preamble_offset + self._vil_offset:
                self._regval += (raw)
        elif self._command == "set_pll_divider_1":
            if self._byte_pos == 1 + preamble_offset + self._vil_offset:
                self._fbdiv = raw << 5
            elif self._byte_pos == 2 + preamble_offset + self._vil_offset:
                self._fbdiv += (raw >> 4) & 0b11111
                self._refdiv = (raw & 0b111) << 3
            elif self._byte_pos == 3 + preamble_offset + self._vil_offset:
                self._refdiv += (raw >> 5) & 0b111
        elif self._command == "set_pll_divider_2":
            if self._byte_pos == 1 + preamble_offset + self._vil_offset:
                self._chipadd = raw
            elif self._byte_pos == 2 + preamble_offset + self._vil_offset:
                self._postdiv1 = raw & 0b111
            elif self._byte_pos == 3 + preamble_offset + self._vil_offset:
                self._postdiv2 = (raw >> 5) & 0b111
        if self._byte_pos == self._frame_len - 1 + preamble_offset:
            # last byte of frame
            self._byte_pos = 0
            self._frame_len = 99
            # check CRC5
            crc5 = raw & 0b11111
            # Return the data frame itself
            return AnalyzerFrame(self._command, self._start_of_frame, frame.end_time, {
                'frame_type': self._frame_type,
                'all': self._all,
                'command': self._cmd,
                'crc5': f"0x{crc5:02X}",
                'chipadd': f"{self._chipadd}" if self._all == "ONE" else "ALL",
                'regadd': self._regadd,
                'regval': f"0x{self._regval:08X}",
                'fbdiv': self._fbdiv,
                'refdiv': self._refdiv,
                'postdiv1': self._postdiv1,
                'postdiv2': self._postdiv2
            })
        else:
            self._byte_pos += 1

