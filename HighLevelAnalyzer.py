# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting, NumberSetting
from time import gmtime, strftime

regs_1385 = {
    0x00: "chip_address",
    0x08: "golden_nonce_counter",
    0x0c: "pll_param",
    0x10: "start_nonce_offset",
    0x14: "hash_counting_number",
    0x18: "ticket_mask",
    0x1c: "misc_control",
}

regs_1387 = {
    0x00: "chip_address",
    0x08: "hash_rate",
    0x0c: "pll_param",
    0x10: "start_nonce_offset",
    0x14: "hash_counting_number",
    0x18: "ticket_mask",
    0x1c: "misc_control",
    0x20: "general_i2c_cmd",
    0x24: "security_i2c_cmd",
    0x28: "signature_input",
    0x2c: "signature_nonce",
    0x30: "signature_id",
    0x34: "security_control_and_status",
    0x38: "job_information",
}

regs_139x = {
    0x00: "chip_address",
    0x04: "hash_rate",
    0x08: "pll0_parameter",
    0x0c: "chip_nonce_offset",
    0x10: "hash_counting_number",
    0x14: "ticket_mask",
    0x18: "misc_control",
    0x1c: "i2c_control",
    0x20: "ordered_clock_enable",
    0x28: "fast_uart_configuration",
    0x2c: "uart_relay",
    0x38: "ticket_mask2",
    0x3c: "core_register_control",
    0x40: "core_register_status",
    0x44: "external_temperature_sensor_read",
    0x48: "error_flag",
    0x4c: "nonce_error_counter",
    0x50: "nonce_overflow_counter",
    0x54: "analog_mux_control",
    0x58: "io_driver_strenght_configuration",
    0x5c: "time_out",
    0x60: "pll1_parameter",
    0x64: "pll2_parameter",
    0x68: "pll3_parameter",
    0x6c: "ordered_clock_monitor",
    0x70: "pll0_divider",
    0x74: "pll1_divider",
    0x78: "pll2_divider",
    0x7c: "pll3_divider",
    0x80: "clock_order_control0",
    0x84: "clock_order_control1",
    0x8c: "clock_order_status",
    0x90: "frequency_sweep_control0",
    0x94: "golden_nonce_for_sweep_return",
    0x98: "returned_group_pattern_status",
    0x9c: "nonce_returned_timeout",
    0xa0: "returned_single_pattern_status",
}

def get_reg_name(chip: int, reg_add: int) -> str:
    """Get the register name by address."""
    try:
        if chip == 1385:
            return regs_1385[reg_add]
        elif chip == 1387:
            return regs_1387[reg_add]
        else:
            return regs_139x[reg_add]
    except KeyError:
        return f"0x{reg_add:02X}"

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    """BM13xx High Level Analyzer."""

    bm_family = ChoicesSetting(['BM1397', 'BM1385'], label='ASIC')
    bm_clkifreq = NumberSetting(label='CLKI frequency [MHz]', min_value=25, max_value=100)

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'set_chipadd': {
            'format': 'Set Address chip@{{data.chip}} CRC={{data.crc}}'
        },
        'write_register': {
            'format': 'Write Register chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} CRC={{data.crc}}'
        },
        'write_register_pll': {
            'format': 'Write Register chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} freq={{data.value}} CRC={{data.crc}}'
        },
        'write_register_misc': {
            'format': 'Write Register chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} baud={{data.value}} CRC={{data.crc}}'
        },
        'chain_inactive': {
            'format': 'Chain Inactive CRC={{data.crc}}'
        },
        'read_register': {
            'format': 'Read Register chip@{{data.chip}} reg@{{data.register}} CRC={{data.crc}}'
        },
        'respond': {
            'format': 'Respond chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} CRC={{data.crc}}'
        },
        'respond_pll': {
            'format': 'Respond chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} freq={{data.value}} CRC={{data.crc}}'
        },
        'respond_misc': {
            'format': 'Respond chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} baud={{data.value}} CRC={{data.crc}}'
        },
        'work': {
            'format': 'Work job_id#{{data.jobid}} midstates_cnt#{{data.midstate}} nbits={{data.nbits}} ntime={{data.ntime}} merkle_root={{data.merkleroot}} CRC={{data.crc}}'
        },
        'nonce': {
            'format': 'Nonce job_id#{{data.jobid}} midstate?{{data.midstate}} nonce={{data.value}} CRC={{data.crc}}'
        },
        # old commands
        'set_pll_divider_1': {
            'format': 'Set PLL Divider1 FBDIV: {{data.fbdiv}} REFDIV: {{data.refdiv}} CRC={{data.crc}}'
        },
        'set_pll_divider_2': {
            'format': 'Set PLL Divider 2 POSTDIV1: {{data.postdiv1}} POSTDIV2: {{data.postdiv2}} CRC={{data.crc}}'
        },
        'set_baud_ops': {
            'format': 'Set Baud OPS chip@{{data.chip}} CRC={{data.crc}}'
        },
        'unknown': {
            'format': 'command: {{data.command}}'
        }
    }

    def get_pll_frequency(self, pll_param: int) -> int:
        """Compute the PLL Frequency based on its paramaters"""
        fb_div = (pll_param >> 16) & 0xfff
        ref_div = (pll_param >> 8) & 0b11111
        post_div_1 = (pll_param >> 4) & 0b111
        post_div_2 = (pll_param >> 0) & 0b111
        return 0 if ref_div==0 or post_div_1==0 or post_div_2==0 else self.bm_clkifreq * fb_div / (ref_div * post_div_1 * post_div_2)

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
        self._chip: int = 1387 if self.bm_family == "BM1387" else 1397
        self._chipadd: int = 0
        self._regadd: int = 0
        self._regval: int = 0
        self._jobid: int = 0
        self._midstates: int = 0
        self._startingnonce: int  = 0
        self._nbits: int  = 0
        self._ntime: int  = 0
        self._merkleroot: int  = 0
        self._crc16: int  = 0
        self._fbdiv: int = 0
        self._refdiv: int = 0
        self._postdiv1: int = 0
        self._postdiv2: int = 0
        # baudrate
        self._baudrate: int = 115200
        self._pll3freq: int = self.get_pll_frequency(0x00700111)
        self._pll3div4: int = 6

    def decode(self, frame: AnalyzerFrame):
        if 'error' in frame.data:
            return
        raw = frame.data['data'][0]
        preamble_offset = 0
        if self.bm_family == "BM1397":
            preamble_offset += 2
        if self._byte_pos == 0:
            self._command = ""
            self._start_of_frame = frame.start_time
            if self.bm_family == "BM1397" and raw == 0xAA:
                self._frame_len = 7
                self._command = "respond"
        if self._command == "respond":
            if self._byte_pos == 0 + preamble_offset:
                self._regval = (raw << 24)
            elif self._byte_pos == 1 + preamble_offset:
                self._regval += (raw << 16)
            elif self._byte_pos == 2 + preamble_offset:
                self._regval += (raw << 8)
            elif self._byte_pos == 3 + preamble_offset:
                self._regval += (raw)
            elif self._byte_pos == 4 + preamble_offset:
                self._chipadd = raw
                if raw == 0x00:
                    self._all = "ALL"
                else:
                    self._all = "ONE"
            elif self._byte_pos == 5 + preamble_offset:
                self._regadd = raw
        else:
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
                if self.bm_family == "BM1387":
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
                elif self.bm_family == "BM1397":
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
            elif self._command == "work":
                if self._byte_pos == 1 + preamble_offset + self._vil_offset:
                    self._jobid = raw
                elif self._byte_pos == 2 + preamble_offset + self._vil_offset:
                    self._midstates = raw
                elif self._byte_pos == 3 + preamble_offset + self._vil_offset:
                    self._startingnonce = (raw << 24)
                elif self._byte_pos == 4 + preamble_offset + self._vil_offset:
                    self._startingnonce += (raw << 16)
                elif self._byte_pos == 5 + preamble_offset + self._vil_offset:
                    self._startingnonce += (raw << 8)
                elif self._byte_pos == 6 + preamble_offset + self._vil_offset:
                    self._startingnonce += (raw)
                elif self._byte_pos == 7 + preamble_offset + self._vil_offset:
                    self._nbits = (raw << 24)
                elif self._byte_pos == 8 + preamble_offset + self._vil_offset:
                    self._nbits += (raw << 16)
                elif self._byte_pos == 9 + preamble_offset + self._vil_offset:
                    self._nbits += (raw << 8)
                elif self._byte_pos == 10 + preamble_offset + self._vil_offset:
                    self._nbits += (raw)
                elif self._byte_pos == 11 + preamble_offset + self._vil_offset:
                    self._ntime = (raw)
                elif self._byte_pos == 12 + preamble_offset + self._vil_offset:
                    self._ntime += (raw << 8)
                elif self._byte_pos == 13 + preamble_offset + self._vil_offset:
                    self._ntime += (raw << 16)
                elif self._byte_pos == 14 + preamble_offset + self._vil_offset:
                    self._ntime += (raw << 24)
                elif self._byte_pos == 15 + preamble_offset + self._vil_offset:
                    self._merkleroot = (raw)
                elif self._byte_pos == 16 + preamble_offset + self._vil_offset:
                    self._merkleroot += (raw << 8)
                elif self._byte_pos == 17 + preamble_offset + self._vil_offset:
                    self._merkleroot += (raw << 16)
                elif self._byte_pos == 18 + preamble_offset + self._vil_offset:
                    self._merkleroot += (raw << 24)
                # following are {self._midstates} midstates of 33 bytes each
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
            if self._byte_pos == self._frame_len - 2 + preamble_offset and self._command == "work":
                self._crc16 = raw << 8
        if self._byte_pos == self._frame_len - 1 + preamble_offset:
            # last byte of frame
            self._byte_pos = 0
            self._frame_len = 99
            # check CRC
            if self._command == "work":
                self._crc16 += raw
            else:
                crc5 = raw & 0b11111
            if self._command == "respond" and raw & 0b10000000 == 0b10000000:
                self._command = "nonce"
            reg_name_or_address = get_reg_name(self._chip, self._regadd) if self._command == "read_register" or self._command == "write_register" or self._command == "respond" else ""
            reg_value_raw = f"0x{self._regval:08X}" if self._command == "write_register" or self._command == "respond" or self._command == "nonce" else ""
            reg_value = reg_value_raw
            analyzer_frame_type = self._command
            if reg_name_or_address == "freqbuf":
                # from kano cgminer source, don't seems to apply to value sent by original T17 FW... 
                fa: float = (self._regval >> 16) & 0xFF
                fb: float = (self._regval >> 8) & 0xFF
                f1: float = (self._regval >> 4) & 0xF
                f2: float = self._regval & 0xF
                freq: float = 0.0 if fb==0 or f1==0 or f2==0 else self.bm_clkifreq*fa/(fb*f1*f2)
                reg_value = f"{freq:10.2f} MHz"
            if reg_name_or_address == "pll0_parameter" or reg_name_or_address == "pll1_parameter" or reg_name_or_address == "pll2_parameter" or reg_name_or_address == "pll3_parameter":
                analyzer_frame_type = analyzer_frame_type + "_pll"
                freq = self.get_pll_frequency(self._regval)
                if reg_name_or_address == "pll3_parameter":
                    self._pll3freq = freq
                reg_value = f"{freq} MHz"
            if reg_name_or_address == "fast_uart_configuration":
                self._pll3div4 = (self._regval >> 24) & 0b1111
            if reg_name_or_address == "misc_control":
                analyzer_frame_type = analyzer_frame_type + "_misc"
                blk_sel = (self._regval >> 16) & 0b1
                bt8d = (self._regval >> 24) & 0b1111 + (self._regval >> 8) & 0b11111
                if blk_sel == 0:
                    reg_value = f"{self.bm_clkifreq / ((bt8d + 1) * 8)} Mbps"
                else:
                    reg_value = f"{self._pll3freq / ((self._pll3div4 + 1) * (bt8d + 1) * 8)} Mbps"
            # Return the data frame itself
            return AnalyzerFrame(analyzer_frame_type, self._start_of_frame, frame.end_time, {
                'frame_type': self._frame_type,
                'all': self._all,
                'command': f"0x{self._cmd:02X}",
                'chip': "" if self._command == "nonce" else f"{self._chipadd}" if self._all == "ONE" else "ALL",
                'register': reg_name_or_address,
                'value': reg_value,
                'value_raw': reg_value_raw,
                'jobid': f"{self._jobid}" if self._command == "work" else f"{self._regadd}" if self._command == "nonce" else "",
                'midstate': f"{self._midstates}" if self._command == "work" else f"{self._chipadd}" if self._command == "nonce" else "", # TODO: not sure what is this byte in case of nonce, values are [0:5] but only 4 midstates per work
                'startingnonce': f"0x{self._startingnonce:08X}" if self._command == "work" else "",
                'nbits': f"0x{self._nbits:08X}" if self._command == "work" else "",
                'ntime': strftime("%Y-%m-%d %H:%M:%S", gmtime(self._ntime)) if self._command == "work" else "",
                'merkleroot': f"0x{self._merkleroot:08X}" if self._command == "work" else "",
                'fbdiv': f"0x{self._fbdiv:02X}",
                'refdiv': f"0x{self._refdiv:02X}",
                'postdiv1': f"0x{self._postdiv1:04X}",
                'postdiv2': f"0x{self._postdiv2:04X}",
                'crc': f"0x{self._crc16:04X}" if self._command == "work" else f"0x{crc5:02X}"
            })
        else:
            self._byte_pos += 1
