# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from distutils import core
from struct import pack, unpack
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
    0xa4: "version_rolling",
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

core_regs_1397 = {
    0: "clock_delay_ctrl",
    1: "process_monitor_ctrl",
    2: "process_monitor_data",
    3: "core_error",
    4: "core_enable",
    5: "hash_clock_ctrl",
    6: "hash_clock_counter",
    7: "sweep_clock_ctrl",
}

def get_core_reg_name(chip: int, reg_id: int) -> str:
    """Get the core register name by address."""
    try:
        if chip == 1397:
            return core_regs_1397[reg_id]
        else:
            return core_regs_1397[reg_id]+"?"
    except KeyError:
        return f"0x{reg_id:02X}"

def swap32(hash: bytearray) -> bytearray:
    """Swap 32bits elements"""
    for i in range(0, len(hash), 4):
        hash[i], hash[i+1], hash[i+2], hash[i+3] = hash[i+3], hash[i+2], hash[i+1], hash[i]
    return hash

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    """BM13xx High Level Analyzer."""

    bm_family = ChoicesSetting(['BM1366', 'BM1397', 'BM1385'], label='ASIC')
    bm_clkifreq = NumberSetting(label='CLKI frequency [MHz]', min_value=25, max_value=100)
    bm_midstates_cnt = NumberSetting(label='Midstates Count', min_value=1, max_value=8)

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
        'write_register_baud': {
            'format': 'Write Register chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} baud={{data.value}} CRC={{data.crc}}'
        },
        'write_register_core': {
            'format': 'Write Register chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}}  core_id={{data.core_id}} core_reg{{data.value}} CRC={{data.crc}}'
        },
        'write_register_i2c': {
            'format': 'Write Register chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} i2c:{{data.value}} CRC={{data.crc}}'
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
        'respond_baud': {
            'format': 'Respond chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} baud={{data.value}} CRC={{data.crc}}'
        },
        'respond_core': {
            'format': 'Respond chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} core_id={{data.core_id}} core_reg_val={{data.value}} CRC={{data.crc}}'
        },
        'respond_i2c': {
            'format': 'Respond chip@{{data.chip}} reg@{{data.register}}={{data.value_raw}} i2c:{{data.value}} CRC={{data.crc}}'
        },
        'work': {
            'format': 'Work job_id#{{data.jobid}} midstates_cnt#{{data.midstate}} nbits={{data.nbits}} ntime={{data.ntime}} CRC={{data.crc}}'
        },
        'nonce': {
            'format': 'Nonce job_id#{{data.jobid}} midstate_id#{{data.midstate}} nonce={{data.value}} CRC={{data.crc}}'
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
        return 0 if ref_div==0 else self.bm_clkifreq * fb_div / (ref_div * (post_div_1+1) * (post_div_2+1))

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
        self._chip: int = 1387 if self.bm_family == "BM1387" else 1397 if self.bm_family == "BM1397" else 1366
        self._chipadd: int = 0
        self._regadd: int = 0
        self._regval: int = 0
        # work
        self._jobid: int = 0
        self._midstates: int = 0
        self._startingnonce: int = 0
        self._nbits: int = 0
        self._ntime: int = 0
        self._merkleroot: int = 0
        self._merkle_root_hash = bytearray(b'')
        self._previous_block_hash = bytearray(b'')
        self._version: int = 0
        self._version_bits: int = 0
        self._crc16: int = 0
        # pll
        self._fbdiv: int = 0
        self._refdiv: int = 0
        self._postdiv1: int = 0
        self._postdiv2: int = 0
        # baudrate
        self._baudrate: int = 115200
        self._pll_uart_freq: int = self.get_pll_frequency(0x00700111)
        self._pll_uart_div4: int = 6
        # i2c
        self._i2cwrite: bool = False

    def decode(self, frame: AnalyzerFrame):
        if 'error' in frame.data:
            return
        raw = frame.data['data'][0]
        preamble_offset = 0
        if self.bm_family == "BM1397" or self.bm_family == "BM1366":
            preamble_offset += 2
        if self._byte_pos == 0:
            self._command = ""
            self._start_of_frame = frame.start_time
            if self.bm_family == "BM1397" and raw == 0xAA:
                self._frame_len = 7
                self._command = "respond"
            if self.bm_family == "BM1366" and raw == 0xAA:
                self._frame_len = 9
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
            elif self._byte_pos == 6 + preamble_offset:
                self._version_bits = (raw << 8)
            elif self._byte_pos == 7 + preamble_offset:
                self._version_bits += (raw)
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
                elif self.bm_family == "BM1397" or self.bm_family == "BM1366":
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
                if self.bm_family == "BM1366" and self._command == "work":
                    self._frame_len += 32
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
                if self.bm_family == "BM1366":
                    if (self._byte_pos >= 15 + preamble_offset + self._vil_offset) and (self._byte_pos < 47 + preamble_offset + self._vil_offset):
                        self._merkle_root_hash.append(raw)
                    elif (self._byte_pos >= 47 + preamble_offset + self._vil_offset) and (self._byte_pos < 79 + preamble_offset + self._vil_offset):
                        self._previous_block_hash.append(raw)
                    elif self._byte_pos == 79 + preamble_offset + self._vil_offset:
                        self._version = (raw)
                    elif self._byte_pos == 80 + preamble_offset + self._vil_offset:
                        self._version += (raw << 8)
                    elif self._byte_pos == 81 + preamble_offset + self._vil_offset:
                        self._version += (raw << 16)
                    elif self._byte_pos == 82 + preamble_offset + self._vil_offset:
                        self._version += (raw << 24)
                else:
                    if self._byte_pos == 15 + preamble_offset + self._vil_offset:
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
            # check CRC
            if self._command == "work":
                self._crc16 += raw
            else:
                crc5 = raw & 0b11111
            if self._command == "respond" and raw & 0b10000000 == 0b10000000:
                self._command = "nonce"
                if self.bm_midstates_cnt == 8:
                    self._jobid = self._regadd & 0b11111000
                    self._midstates = self._regadd & 0b111
                elif self.bm_midstates_cnt == 4:
                    self._jobid = self._regadd & 0b11111100
                    self._midstates = self._regadd & 0b11
                elif self.bm_midstates_cnt == 2:
                    self._jobid = self._regadd & 0b11111110
                    self._midstates = self._regadd & 0b1
                else:
                    self._jobid = self._regadd
                    self._midstates = 0
            reg_name_or_address = get_reg_name(self._chip, self._regadd) if self._command == "read_register" or self._command == "write_register" or self._command == "respond" else ""
            reg_value_raw = f"0x{self._regval:08X}" if self._command == "write_register" or self._command == "respond" or self._command == "nonce" else ""
            reg_value = reg_value_raw
            core_id = 0
            analyzer_frame_type = self._command
            if reg_name_or_address == "freqbuf":
                # from kano cgminer source, don't seems to apply to value sent by original T17 FW... 
                fa: float = (self._regval >> 16) & 0xFF
                fb: float = (self._regval >> 8) & 0xFF
                f1: float = (self._regval >> 4) & 0xF
                f2: float = self._regval & 0xF
                freq: float = 0.0 if fb==0 or f1==0 or f2==0 else self.bm_clkifreq*fa/(fb*f1*f2)
                reg_value = f"{freq:10.2f} MHz"
            elif reg_name_or_address == "pll0_parameter" or reg_name_or_address == "pll1_parameter" or reg_name_or_address == "pll2_parameter" or reg_name_or_address == "pll3_parameter":
                analyzer_frame_type = analyzer_frame_type + "_pll"
                freq = self.get_pll_frequency(self._regval)
                if reg_name_or_address == "pll3_parameter" and self.bm_family == "BM1397":
                    self._pll_uart_freq = freq
                if reg_name_or_address == "pll1_parameter" and self.bm_family == "BM1366":
                    self._pll_uart_freq = freq
                reg_value = f"{freq} MHz"
            elif reg_name_or_address == "fast_uart_configuration":
                if self.bm_family == "BM1397":
                    self._pll_uart_div4 = (self._regval >> 24) & 0b1111
                if self.bm_family == "BM1366":
                    analyzer_frame_type = analyzer_frame_type + "_baud"
                    self._pll_uart_div4 = (self._regval >> 20) & 0b1111
                    bclk_sel = (self._regval >> 26) & 0b1
                    bt8d = (self._regval >> 8) & 0xff
                    baud : float = 0.0
                    if bclk_sel == 0:
                        baud = self.bm_clkifreq / ((bt8d + 1) * 8)
                    else:
                        baud = self._pll_uart_freq / ((self._pll_uart_div4 + 1) * (bt8d + 1) * 2)
                    if baud > 1.0:
                        reg_value = f"{baud:10.6f}Mbps"
                    else:
                        baud = baud * 1E6
                        reg_value = f"{baud:10.0f}bps"
            elif reg_name_or_address == "misc_control":
                if self.bm_family == "BM1397":
                    analyzer_frame_type = analyzer_frame_type + "_baud"
                    bclk_sel = (self._regval >> 16) & 0b1
                    bt8d = ((self._regval >> 24) & 0b1111) + ((self._regval >> 8) & 0b11111)
                    baud : float = 0.0
                    if bclk_sel == 0:
                        baud = self.bm_clkifreq / ((bt8d + 1) * 8)
                    else:
                        baud = self._pll_uart_freq / ((self._pll_uart_div4 + 1) * (bt8d + 1) * 8)
                    if baud > 1.0:
                        reg_value = f"{baud:10.6f}Mbps"
                    else:
                        baud = baud * 1E6
                        reg_value = f"{baud:10.0f}bps"
            elif reg_name_or_address == "core_register_control" or reg_name_or_address == "core_register_status":
                analyzer_frame_type = analyzer_frame_type + "_core"
                if reg_name_or_address == "core_register_control":
                    core_id = (self._regval >> 16) & 0xff
                    core_reg_id = (self._regval >> 8) & 0xf
                    core_reg_val = (self._regval >> 0) & 0xff
                    if (self._regval >> 31) & 0b1 == 0b1:
                        reg_value = f"WR@{get_core_reg_name(self._chip, core_reg_id)}=0x{core_reg_val:02X}"
                    else:
                        reg_value = f"RD@{get_core_reg_name(self._chip, core_reg_id)}"
                else:
                    core_id = (self._regval >> 16) & 0xffff
                    core_reg_val = (self._regval >> 0) & 0xffff
                    reg_value = f"0x{core_reg_val:04X}"
            elif reg_name_or_address == "i2c_control" and self._command != "read_register":
                analyzer_frame_type = analyzer_frame_type + "_i2c"
                i2c_addr = (self._regval >> 17) & 0x7f
                i2c_reg_addr = (self._regval >> 8) & 0xff
                i2c_reg_val = (self._regval >> 0) & 0xff
                if self._command == "write_register":
                    if ((self._regval >> 16) & 0b1) == 0b1: # RD#/WR
                        self._i2cwrite = True
                        reg_value = f"WR@0x{i2c_addr:02X}@0x{i2c_reg_addr:02X}=0x{i2c_reg_val:02X}"
                    else:
                        self._i2cwrite = False
                        reg_value = f"RD@0x{i2c_addr:02X}@0x{i2c_reg_addr:02X}"
                elif self._command == "respond":
                    if ((self._regval >> 31) & 0b1) == 0b1: # BUSY
                        reg_value = f"busy"
                    else:
                        if self._i2cwrite: # bug: always false (as the __init__ value), look like the assign above are not remembered...
                            reg_value = f"Write done"
                        else:
                            reg_value = f"RD@0x{i2c_addr:02X}@0x{i2c_reg_addr:02X}=0x{i2c_reg_val:02X}"
            merkle_root = ""
            prev_hash = ""
            block_vers = ""
            if self._command == "work":
                if self.bm_family == "BM1366":
                    merkle_root = ''.join(format(x, '02x') for x in swap32(self._merkle_root_hash)) if len(self._merkle_root_hash) > 0 else "None"
                    prev_hash = ''.join(format(x, '02x') for x in swap32(self._previous_block_hash)) if len(self._previous_block_hash) > 0 else "None"
                    block_vers = f"0x{self._version:08X}"
                else:
                    merkle_root = f"{self._merkleroot:08X}"
            # init vars                                
            self._byte_pos = 0
            self._frame_len = 99
            self._merkle_root_hash = bytearray(b'')
            self._previous_block_hash = bytearray(b'')
            # Return the data frame itself
            return AnalyzerFrame(analyzer_frame_type, self._start_of_frame, frame.end_time, {
                'frame_type': self._frame_type,
                'all': self._all,
                'command': f"0x{self._cmd:02X}",
                'chip': "" if self._command == "nonce" else f"{self._chipadd}" if self._all == "ONE" else "ALL",
                'register': reg_name_or_address,
                'value': reg_value,
                'value_raw': reg_value_raw,
                'versionbits': f"0x{self._version_bits:04X}" if self._command == "nonce" and self.bm_family == "BM1366" else "",
                'core_id': f"{core_id}" if (reg_name_or_address == "core_register_control" or reg_name_or_address == "core_register_status") else "",
                'jobid': f"{self._jobid}" if (self._command == "work" or self._command == "nonce") else "",
                'midstate': f"{self._midstates}" if (self._command == "work" or self._command == "nonce") else "",
                'startingnonce': f"0x{self._startingnonce:08X}" if self._command == "work" else "",
                'nbits': f"0x{self._nbits:08X}" if self._command == "work" else "",
                'ntime': strftime("%Y-%m-%d %H:%M:%S", gmtime(self._ntime)) if self._command == "work" else "",
                'merkleroot': merkle_root,
                'prevhash': prev_hash,
                'blockvers': block_vers,
                'fbdiv': f"0x{self._fbdiv:02X}",
                'refdiv': f"0x{self._refdiv:02X}",
                'postdiv1': f"0x{self._postdiv1:04X}",
                'postdiv2': f"0x{self._postdiv2:04X}",
                'crc': f"0x{self._crc16:04X}" if self._command == "work" else f"0x{crc5:02X}"
            })
        else:
            self._byte_pos += 1
