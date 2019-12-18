import usb
import struct
import sys
import os
import io
from pathlib import Path
from timeit import default_timer as timer
from .constants import *
import shutil

NXUSB_VERSION_MAJOR = 0
NXUSB_VERSION_MINOR = 0
NXUSB_VERSION_PATCH = 1

class usb_tool:
	def __init__(self):
		self.dev = None
		self.out_ep = None
		self.in_ep = None
		self.is_connected = False
		self.open_file = None

		self.UsbModeMap = {
			UsbMode.UsbMode_Exit.value : self.exit,
			UsbMode.UsbMode_Ping.value : self.ping,

			UsbMode.UsbMode_OpenFile.value : self.OpenFile,
			UsbMode.UsbMode_ReadFile.value : self.ReadFile,
			UsbMode.UsbMode_WriteFile.value : self.WriteFile,
			UsbMode.UsbMode_TouchFile.value : self.TouchFile,
			UsbMode.UsbMode_DeleteFile.value : self.DeleteFile,
			UsbMode.UsbMode_RenameFile.value : self.RenameFile,
			UsbMode.UsbMode_GetFileSize.value : self.GetFileSize,
			UsbMode.UsbMode_CloseFile.value : self.CloseFile,

			UsbMode.UsbMode_OpenDir.value : self.OpenDir,
			UsbMode.UsbMode_ReadDir.value : self.ReadDir,
			UsbMode.UsbMode_DeleteDir.value : self.DeleteDir,
			UsbMode.UsbMode_DeleteDirRecursively.value : self.DeleteDirRecursively,
			UsbMode.UsbMode_GetDirTotal.value : self.GetDirTotal,
			UsbMode.UsbMode_GetDirTotalRecursively.value : self.GetDirTotalRecursively,
			UsbMode.UsbMode_RenameDir.value : self.RenameDir,
			UsbMode.UsbMode_TouchDir.value : self.TouchDir,

			UsbMode.UsbMode_OpenDevice.value : self.OpenDevice,
			UsbMode.UsbMode_ReadDevices.value : self.ReadDevices,
			UsbMode.UsbMode_GetTotalDevices.value : self.GetTotalDevices,
		}

	def init(self):
		print("Starting Switch connection")
		if self.wait_for_switch_to_connect(silent = True): #Populates self.dev when the switch is connected
			try:
				dev = self.dev
				dev.reset()
				dev.set_configuration()
				cfg = dev.get_active_configuration()

				ep = self.get_endpoints(cfg)
				out_ep = ep[1]
				in_ep = ep[0]

				assert out_ep is not None
				assert in_ep is not None

				self.out_ep = out_ep
				self.in_ep = in_ep

				if not self.attempt_handshake():
					print("Handshake failed")
					return

				self.is_connected = True
				return True
			except Exception as e:
				print("Error: Failed to init switch connection ~ {}".format(e))
		else:
			print("Can't init switch connection")

	def readUSB(self, length):
		if length:
			return self.in_ep.read(length, timeout=0)

	def writeUSB(self, outstruct):
		if outstruct:
			self.dev.write(endpoint = self.out_ep, data = outstruct, timeout = 1000)

	def writeUSBReturnCode(self, code):
		outstruct = struct.pack("<l", code)
		print("Writing USBReturnCode {}".format(UsbReturnCode(code)))
		self.writeUSB(outstruct)

	def writeUSBReturnSuccess(self):
		self.writeUSBReturnCode(UsbReturnCode.UsbReturnCode_Success.value)

	def attempt_handshake(self):
		try:
			io_in = self.in_ep.read(0x10, timeout=0)
			magic = struct.unpack('<Q', io_in[0x0:0x8])[0]
			if not magic == NXUSB_MAGIC:
				print("Invalid USB Magic")
				return False

			macro = struct.unpack('<B', io_in[0x8:0x9])[0]
			minor = struct.unpack('<B', io_in[0x9:0xA])[0]
			major = struct.unpack('<B', io_in[0xA:0xB])[0]

			self.writeUSBReturnSuccess()

			outstruct = struct.pack("<Q3B5x", NXUSB_MAGIC, NXUSB_VERSION_MAJOR, NXUSB_VERSION_MINOR, NXUSB_VERSION_PATCH)
			self.dev.write(endpoint = self.out_ep, data = outstruct, timeout = 1000)

			print("Handshake successful, switch client version {}.{}.{}".format(major, minor, macro))
			return True

		except Exception as e:
			print("Handshake error ~ {}".format(e))
			return False

	# Find the switch
	def find_switch(self, silent = False):
		if not silent:
			print("Searcing for Nintendo Switch (VendorID: {}, ProductID: {}".format(str(SWITCH_VENDOR_ID), str(SWITCH_PRODUCT_ID)))
		return usb.core.find(idVendor=SWITCH_VENDOR_ID, idProduct=SWITCH_PRODUCT_ID)

	# Wait for the switch to connect, set a timeout or wait indefinitely
	# Silent mutes the find function but doesn't mute printouts
	# True if found | False if not found
	def wait_for_switch_to_connect(self, timeout = None, silent = False):
		dev = None
		# loop until switch is found.
		starttime = timer()
		while (dev is None):
			if timeout:
				if (timer() > (starttime + timeout)):
					print("Switch connection timeout exceeded")
					break
			dev = self.find_switch(silent = silent)
		self.dev = dev
		if dev:
			print("Found switch")
			return True
		else:
			print("Failed to find switch")
			return False

	def get_endpoints(self, cfg):
		print("Getting endpoints")
		print("==============================================================")

		in_ep = _get_in_endpoint(cfg)
		print("In:")
		print(in_ep)

		out_ep = _get_out_endpoint(cfg)
		print("Out:")
		print(out_ep)

		print("==============================================================")
		return(in_ep, out_ep)

	#Finished
	def exit(self, size=None):
		print("Received USB exit command...")
		self._exit()

	def ping(self, size):
		return UsbReturnCode.UsbReturnCode_Success.value

	def OpenFile(self, size):
		io_in = self.readUSB(size)
		if io_in:
			print(io_in)
			path_to_open = struct.unpack('<{}s'.format(size), io_in[0x0:size])[0]
			print("Path: {}".format(path_to_open))

			status = UsbReturnCode.UsbReturnCode_Success.value
			try:
				self.open_file = path_to_open
			except Exception as e:
				print("Failed to open file ~ {}".format(e))
				status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value

		return status

	#Not tested
	def ReadFile(self, size):
		io_in = self.readUSB(size)
		if io_in:
			read_size = struct.unpack('<Q'.format(size), io_in[0x0:0x8])[0]
			read_offset = struct.unpack('<Q'.format(size), io_in[0x8:0x10])[0]
			print("Read size {}".format(read_size))
			print("Read read_offset {}".format(read_offset))
			status = UsbReturnCode.UsbReturnCode_Success.value

			with open(self.open_file, "rb") as open_file:
				try:
					open_file.seek(read_offset)
					data = open_file.read(read_size)
					print("Read data {}".format(data))
				except Exception as e:
					try:
						print("Error reading file {} ~ {}".format(path_to_open, e))
					except:
						print("Error reading file!! {}".format(e))
					return UsbReturnCode.UsbReturnCode_FailedOpenFile.value
			try:
				self.writeUSB(data)
				print("successfully wrote contents to usb")
			except Exception as e:
				print("Failed to write file contents to usb ~ {}".format(e))
				return UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		else:
			return UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		return -1

	#Not tested
	def WriteFile(self, size):
		io_in = self.readUSB(size)
		if io_in:
			write_size = struct.unpack('<Q'.format(size), io_in[0x0:0x8])[0]
			write_offset = struct.unpack('<Q'.format(size), io_in[0x8:0x10])[0]
			data_in = self.readUSB(write_size)
			bytes_in = struct.unpack('<{}b'.format(write_size))

			with open(self.open_file, "w") as open_file:
				try:
					open_file.seek(read_offset)
					open_file.write(bytes_in)
					status = UsbReturnCode.UsbReturnCode_Success.value
				except Exception as e:
					try:
						print("Error writing to file {} ~ {}".format(path_to_open, e))
					except:
						print("Error writing to file!! {}".format(e))
					status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		return status

	def CloseFile(self, size = None):
		if self.open_file:
			self.open_file = None
			status = UsbReturnCode.UsbReturnCode_Success.value
		else:
			status = UsbReturnCode.UsbReturnCode_FileNotOpen.value
		return status

	def TouchFile(self, size):
		io_in = self.readUSB(size)
		print(io_in)
		path_to_open = struct.unpack('<{}s'.format(size), io_in[0x0:size])[0]
		print("Path: {}".format(path_to_open))

		status = UsbReturnCode.UsbReturnCode_Success.value
		try:
			if os.path.exists(path_to_open):
				if os.path.isdir(path_to_open):
					status = UsbReturnCode.UsbReturnCode_FailedTouchFile.value
				elif os.path.isfile(path_to_open):
					pass
				else:
					raise
			else:
				with open(path_to_open, "w+"):
					pass
		except Exception as e:
			try:
				print("Failed to touch file {}".format(path_to_open, e))
			except:
				print("Failed to touch file!!")
			status = UsbReturnCode.UsbReturnCode_FailedTouchFile.value

		return status

	def DeleteFile(self, size):
		io_in = self.readUSB(size)
		print(io_in)
		path_to_open = struct.unpack('<{}s'.format(size), io_in[0x0:size])[0]
		print("Path: {}".format(path_to_open))

		status = UsbReturnCode.UsbReturnCode_Success.value

		if os.path.exists(path_to_open):
			if os.path.isdir(path_to_open):
				status = UsbReturnCode.UsbReturnCode_FailedDeleteFile.value
			elif os.path.isfile(path_to_open):
				print("Removing {}".format(Path))
				os.remove(path_to_open)
			else:
				raise
		else:
			status = UsbReturnCode.UsbReturnCode_FailedDeleteFile.value

		return status

	#IDK what I'm doing wrong
	def RenameFile(self, size):
		pass
		# io_in = self.readUSB(size)
		# print(io_in)
		# size_1 = struct.unpack('<Q', io_in[0x0:0x8])[0]
		# print("Size_1: {}".format(size_1))
		# size_2 = struct.unpack('<Q', io_in[0x8:0x10])[0]
		# print("Size_2: {}".format(size_2))
		# string_1 = struct.unpack('<{}s'.format(size_1), io_in[0x10:0x10+size_1])[0]
		# string_2 = struct.unpack('<{}s'.format(size_2), io_in[0x10+size_1:0x10+size_1+size_2])[0]
		# print("Filename_1: {}, Filename_2: {}".format(string_1, string_2))
		# return UsbReturnCode.UsbReturnCode_Success.value

	#Returns 0x0 on fail
	def GetFileSize(self, size):
		io_in = self.readUSB(size)
		print(io_in)
		path_to_open = struct.unpack('<{}s'.format(size), io_in[0x0:size])[0]
		print("Path: {}".format(path_to_open))

		try:
			if os.path.exists(path_to_open):
				if os.path.isdir(path_to_open):
					status = UsbReturnCode.UsbReturnCode_FailedToGetFileSize.value
				elif os.path.isfile(path_to_open):
					filesize = os.path.getsize(path_to_open)
				else:
					raise
			else:
				filesize = 0x0
		except Exception as e:
			try:
				print("Failed to get file size {} ~ {}".format(path_to_open, e))
			except:
				print("Failed to get file size!! ~ {}".format(e))
			filesize = 0x0

		outstruct = struct.pack('<Q', filesize)
		self.writeUSB(outstruct)
		return -1 #Prevents the sending of the usb return code

	def OpenDir(self, size):
		io_in = self.readUSB(size)
		if io_in:
			print(io_in)
			path_to_open = struct.unpack('<{}s'.format(size), io_in[0x0:size])[0]

		status = UsbReturnCode.UsbReturnCode_Success.value

		try:
			if os.path.exists(path_to_open):
				if os.path.isdir(path_to_open):
					os.chdir(path)
				elif os.path.isfile(path_to_open):
					status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value
				else:
					raise
			else:
				status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value
		except Exception as e:
			try:
				print("Failed to open dir {} ~ {}".format(path_to_open, e))
			except:
				print("Failed to open dir! ~ {}".format(e))
			status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value

		return status

	def ReadDir(self, size):
		pass

	def DeleteDir(self, size):
		io_in = self.readUSB(size)
		if io_in:
			print(io_in)
			path_to_open = struct.unpack('<{}s'.format(size), io_in[0x0:size])[0]

		status = UsbReturnCode.UsbReturnCode_Success.value

		try:
			if os.path.exists(path_to_open):
				if os.path.isdir(path_to_open):
					try:
						os.rmdir(path)
					except Exception as e:
						print("Error deleting dir {} ~ {}".format(path, e))
						status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value
				elif os.path.isfile(path_to_open):
					status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value
				else:
					raise
			else:
				status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value
		except Exception as e:
			try:
				print("Failed to delete dir {} ~ {}".format(path_to_open, e))
			except:
				print("Failed to delete dir! ~ {}".format(e))
			status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value

		return status

	#Not written yet switch-side
	def DeleteDirRecursively(self, size):
		pass

	def GetDirTotal(self, size):
		pass

	def GetDirTotalRecursively(self, size):
		pass

	def RenameDir(self, size):
		pass

	def TouchDir(self, size):
		pass

	def OpenDevice(self, size):
		pass

	def ReadDevices(self, size):
		pass

	def GetTotalDevices(self, size):
		pass

	#returns mode if mode was found
	def mode_poll(self):
		# try:
		print("Awaiting command...")
		try:
			io_in = self.in_ep.read(0x10, timeout=0)
		except usb.core.USBError as e:
			print("Error polling USB (Device disconnnected?) reinitializing...")
			return
		print(io_in)
		mode = struct.unpack('<B', io_in[0x0:0x1])[0]
		padding = struct.unpack('<7?', io_in[0x1:0x8])[0]
		size = struct.unpack('<Q', io_in[0x8:0x10])[0]

		print("Mode: {}, Size: {}".format(mode, size))

		print("Received Command {}".format(UsbMode(mode)))

		try:
			function = self.UsbModeMap[mode]
		except Exception as e:
			try:
				print("Error selecting mode: {} ~ {}".format(mode,e))
			except:
				print("Error selecting mode! {}".format(e))

		# try:
		result = function(size)
		if not result == -1:
			self.writeUSBReturnCode(result)
		# except Exception as e:
		# 	print("Error executing USB command {}, size {} ~ {}".format(UsbMode(mode), size, e))

		# except Exception as e:
		# 	print("Error while polling ~ {}".format(e))
		# 	self._exit()
		# 	input()
		# 	return

	def _exit(self):
		sys.exit("Exiting...")


	def get_cwd(self):
		pass












def _get_endpoint(direction, cfg):
	is_ep = lambda ep: usb.util.endpoint_direction(ep.bEndpointAddress) == direction
	return usb.util.find_descriptor(cfg[(0,0)], custom_match = is_ep)

def _get_out_endpoint(cfg):
	return _get_endpoint(usb.util.ENDPOINT_OUT, cfg)

def _get_in_endpoint(cfg):
	return _get_endpoint(usb.util.ENDPOINT_IN, cfg)

def unpack_string(struct, length):
	pass