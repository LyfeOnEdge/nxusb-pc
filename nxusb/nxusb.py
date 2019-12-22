import usb
import struct
import sys
import os
import shutil
from timeit import default_timer as timer
from .constants import *
from .webhandler import download_object

NXUSB_VERSION_MAJOR = 0
NXUSB_VERSION_MINOR = 0
NXUSB_VERSION_PATCH = 1

class unpackError(BaseException):
	pass #Raised when there is an issue unpacking usb data
class overlapError(BaseException):
	pass #Raised when usb command values overlap
class usbError(BaseException):
	pass #Raised when there is an issue with reading or writing usb
class fileError(BaseException):
	pass #Raised whene there is an issue with interacting with a file
class notImplemented(BaseException):
	pass #Raised when an unimplemented method is called

class usb_tool:
	def __init__(self):
		self.dev = None
		self.out_ep = None
		self.in_ep = None
		self.is_connected = False
		self.open_file = None
		self.cwd = None

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
			UsbMode.UsbMode_GetWebDownload.value : self.GetWebDownload,
		}

	def addUSBcommand(self, value, callback):
		if not value in self.UsbModeMap.keys():
			self.UsbModeMap[value] = callback
		else:
			print("Error adding usb command, value overlap")
			raise overlapError

	def addUSBcommands(self, command_list):
		for value, callback in command_list:
			self.addUSBcommand(value, callback)

	#Tested
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
					return False

				self.is_connected = True
				return True
			except Exception as e:
				print("Error: Failed to init switch connection ~ {}".format(e))
				return None
		else:
			print("Can't init switch connection")
			return False

	#-------------------------------
	#Handshake struct:
	#The first 8 bytes are magic [0x4E58555342]
	#Then 3 bytes for the version [Macro, micro, major]
	#Then 5 bytes of padding
	#----------------------------
	#Handshake protocol
	#The switch writes a handshake struct of length 0x10
	#The pc writes a success code
	#The pc writes a handshake struct
	def attempt_handshake(self):
		try:
			io_in = self.in_ep.read(0x10, timeout=0)
			magic = unpack_unsigned_long_long(io_in[0x0:0x8])
			if not magic == NXUSB_MAGIC:
				print("Invalid USB Magic")
				return False

			try:
				macro = unpack_byte(io_in[0x8:0x9])
				minor = unpack_byte(io_in[0x9:0xA])
				major = unpack_byte(io_in[0xA:0xB])
			except Exception as e:
				print("Handshake unpack error: {}".format(e))
				return False
			self.writeUSBReturnSuccess()

			outstruct = struct.pack("<Q3B5x", NXUSB_MAGIC, NXUSB_VERSION_MAJOR, NXUSB_VERSION_MINOR, NXUSB_VERSION_PATCH)
			self.writeUSB(outstruct)

			print("Handshake successful, switch client version {}.{}.{}".format(major, minor, macro))
			return True

		except Exception as e:
			print("Handshake error ~ {}".format(e))
			return False

	#Call when app is ready
	def mainloop(self):
		while True:
			self.mode_poll()


#Utility functions
	# Find a ready switch, returns usb device
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

	#Pass device config, get endpoints in tuple
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
		assert in_ep is not None
		assert out_ep is not None
		return(in_ep, out_ep)

	#Finished
	def exit(self, size=None, data = None):
		print("Received USB exit command...")
		self._exit()

	def _exit(self):
		sys.exit("Exiting...")

#Read and write functions
	def readUSB(self, length, timeout = 0):
		if length:
			try:
				data = self.in_ep.read(length, timeout = timeout)
				print("Received data - {}".format(data))
				return data
			except Exception as e:
				print("Error reading USB ~ {}".format(e))
		else:
			return False
		
	def readUSBRaw(self, length, timeout = 0):
        return self.in_ep.read(length, timeout = timeout).tobytes()

	#Returns True if successful
	def writeUSB(self, outstruct, timeout = 1000):
		try:
			if outstruct:
				self.dev.write(endpoint = self.out_ep, data = outstruct, timeout = timeout)
				return True
			else:
				pass
		except Exception as e:
			print("Error writing to USB ~ {}".format(e))

	#Shortcut to write usb retrun codes
	#Returns True if sucessful
	def writeUSBReturnCode(self, code):
		if code is None:
			print("Error writing USB return code. Return code is None.")
			raise usbError
		outstruct = struct.pack("<l", code)
		print("Writing USBReturnCode {}".format(UsbReturnCode(code)))
		return self.writeUSB(outstruct)

	#Shortcut to write usb success code
	#Returns True if sucessful
	def writeUSBReturnSuccess(self):
		return self.writeUSBReturnCode(UsbReturnCode.UsbReturnCode_Success.value)

		#Writes a file given it's path
	def writeUSBfile(file_path, range_size, range_offset):
		with open(file_path) as f:
			return self._writeUSBfile(f, range_size, range_offset)

		#Writes a file object to USB in 1MiB chunks
	def _writeUSBfile(file_object, range_size, range_offset):
		try:
			f = file_object
			f.seek(range_offset)

			curr_off = 0x0
			end_off = range_size
			read_size = 0x100000 # 1MiB

			while curr_off < end_off:
				if curr_off + read_size >= end_off:
					read_size = end_off - curr_off

				buf = f.read(read_size)
				if not self.writeUSB(buf):
					raise usbError
				curr_off += read_size
				print("reading {} - {}".format(curr_off, end_off))

			return True
		except Exception as e:
			print("Error writing file to usb range_size: {}, range_offset {}".format(range_size, range_offset))
			return False


#Usb Commands
	#Test ping
	def ping(self, size):
		return UsbReturnCode.UsbReturnCode_Success.value

	#Works
	def OpenFile(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(io_in, size)
			print("Opening path: {}".format(path_to_open))

			try:
				if os.path.isfile(path_to_open):
					self.open_file = path_to_open
					status = UsbReturnCode.UsbReturnCode_Success.value
				else:
					print("Error in method OpenFile ~ File does not exits")
					self.open_file = None
					status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value
			except Exception as e:
				print("Failed to open file ~ {}".format(e))
				status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value

		return status

	#Not tested
	def ReadFile(self, size, io_in):
		if io_in:
			read_size = unpack_unsigned_long_long(io_in[0x0:0x8])
			read_offset = unpack_unsigned_long_long(io_in[0x8:0x10])
			print("Read size {}".format(read_size))
			print("Read read_offset {}".format(read_offset))

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

	#Working
	def WriteFile(self, size, io_in):
		if io_in:
			write_size = unpack_unsigned_long_long(io_in[0x0:0x8])
			write_offset = unpack_unsigned_long_long(io_in[0x8:0x10])
			data_in = self.readUSB(write_size)
			data_in = unpack_string(data_in, write_size)

			status = -1
			with open(self.open_file, "wb") as open_file:
				try:
					open_file.seek(write_offset)
					open_file.write(data_in)
					print("Wrote {} to file {}".format(data_in, self.open_file))
				except Exception as e:
					try:
						print("Error writing to file {} ~ {}".format(path_to_open, e))
					except:
						print("Error writing to file!! {}".format(e))
					status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedOpenFile.value

		return status

	def CloseFile(self, size, io_in):
		if size:
			print("CloseFile command passed unexpected data")
			raise fileError
		if self.open_file:
			self.open_file = None
			status = UsbReturnCode.UsbReturnCode_Success.value
		else:
			status = UsbReturnCode.UsbReturnCode_FileNotOpen.value

		return status

	#Tested, works.
	def TouchFile(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(io_in, size)
			print("Path: {}".format(path_to_open))
			try:
				if os.path.exists(path_to_open):
					if os.path.isdir(path_to_open):
						status = UsbReturnCode.UsbReturnCode_FailedTouchFile.value
					elif os.path.isfile(path_to_open):
						status = UsbReturnCode.UsbReturnCode_Success.value #If it's already a valid file use normal return code
					else:
						raise fileError
				else:
					with open(path_to_open, "w+"):
						status = UsbReturnCode.UsbReturnCode_Success.value #If it's not a valid file, make the file and use normal return code
			except Exception as e:
				try:
					print("Failed to touch file {}".format(path_to_open, e))
				except:
					print("Failed to touch file!!")
				status = UsbReturnCode.UsbReturnCode_FailedTouchFile.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedTouchFile.value

		return status

	#Tested, works.
	def DeleteFile(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(io_in, size)
			print("Path: {}".format(path_to_open))
			if os.path.exists(path_to_open):
				if os.path.isdir(path_to_open):
					status = UsbReturnCode.UsbReturnCode_FailedDeleteFile.value
				elif os.path.isfile(path_to_open):
					print("Removing {}".format(path_to_open))
					os.remove(path_to_open)
					status = UsbReturnCode.UsbReturnCode_Success.value
				else:
					raise fileError
			else:
				status = UsbReturnCode.UsbReturnCode_FailedDeleteFile.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedDeleteFile.value

		return status

	#IDK what I'm doing wrong. I can't figure out how to decode the sent bytes.
	def RenameFile(self, size, io_in):
		pass
		# if io_in:
		# 	try:
		# 		size_1 = unpack_unsigned_long_long(io_in[0x0:0x8])
		# 		print("Size_1: {}".format(size_1))
		# 		size_2 = unpack_unsigned_long_long(io_in[0x8:0x10])
		# 		print("Size_2: {}".format(size_2))
		# 		string_1 = unpack_string(io_in[0x10:0x10 + size_1], size_1)
		# 		# string_2 = io_in[0x10+size_1:0x10+size_1+size_2].tobytes().decode('utf-8')'
		# 		string_2 = "test"
		# 		print("Filename_1: {}, Filename_2: {}".format(string_1, string_2))
		# 		status = UsbReturnCode.UsbReturnCode_Success.value
		# 	except Exception as e:
		# 		print("Error unpacking file rename strings / sizes ~ {}".format(e))
		# 		status = UsbReturnCode.UsbReturnCode_FailedRenameFile.value
		# else:
		# 	status = UsbReturnCode.UsbReturnCode_FailedRenameFile.value

		# return status

	#Returns 0x0 on fail, not tested
	def GetFileSize(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(io_in, size)
			print("Path: {}".format(path_to_open))

			try:
				if os.path.exists(path_to_open):
					if os.path.isdir(path_to_open):
						filesize = 0x0
					elif os.path.isfile(path_to_open):
						filesize = os.path.getsize(path_to_open)
					else:
						raise fileError
				else:
					filesize = 0x0
			except Exception as e:
				try:
					print("Failed to get file size {} ~ {}".format(path_to_open, e))
				except:
					print("Failed to get file size!! ~ {}".format(e))
				filesize = 0x0
		else:
			filesize = 0x0
		outstruct = struct.pack('<Q', filesize)
		self.writeUSB(outstruct)
		return -1 #Prevents the sending of the usb return code

	def OpenDir(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(size, io_in)

			try:
				if os.path.exists(path_to_open):
					if os.path.isdir(path_to_open):
						self.cwd = path_to_open
						status = UsbReturnCode.UsbReturnCode_Success.value
					elif os.path.isfile(path_to_open):
						self.cwd = None
						status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value
					else:
						self.cwd = None
						raise fileError
				else:
					self.cwd = None
					status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value
			except Exception as e:
				print("Failed to change working dir ~ {}".format(e))
				status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedOpenDir.value

		return status
		
	def ChangeDir(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(size, io_in)
			
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
		else:
			status = UsbReturnCode.UsbReturnCode_PollError.value
		
		return status


	def ReadDir(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(size, io_in)
			print(path_to_open)
			return UsbReturnCode.UsbReturnCode_Success.value

	#Works
	def _DeleteDir(self, size, io_in, recursive = False):
		if io_in:
			path_to_open = unpack_string(io_in, size)

			try:
				if os.path.exists(path_to_open):
					if os.path.isdir(path_to_open):
						if recursive:
							shutil.rmtree(path_to_open) #Removes dir recursively
						else:
							os.rmdir(path_to_open) #Removes dir non-recursively
						status = UsbReturnCode.UsbReturnCode_Success.value
					elif os.path.isfile(path_to_open):
						status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value
					else:
						raise fileError
				else:
					status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value
			except Exception as e:
				try:
					print("Failed to delete dir [recursive: {}] {} ~ {}".format(recursive, path_to_open, e))
				except:
					print("Failed to delete dir [recursive: {}]! ~ {}".format(recursive, e))
				status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedDeleteDir.value

		return status

	#Works
	def DeleteDir(self, size, io_in):
		return self._DeleteDir(size, io_in, recursive = False)

	#Not written yet switch-side, probably works though
	def DeleteDirRecursively(self, size, io_in):
		return self._DeleteDir(size, io_in, recursive = True)

	def GetDirTotal(self, size, io_in):
		raise notImplemented

	def GetDirTotalRecursively(self, size, io_in):
		raise notImplemented

	def RenameDir(self, size, io_in):
		raise notImplemented

	def TouchDir(self, size, io_in):
		if io_in:
			path_to_open = unpack_string(io_in, size)
			print("Path: {}".format(path_to_open))
			try:
				if os.path.exists(path_to_open):
					if os.path.isdir(path_to_open):
						status = UsbReturnCode.UsbReturnCode_Success.value
					elif os.path.isfile(path_to_open):
						status = UsbReturnCode.UsbReturnCode_FailedTouchDir.value
					else:
						raise fileError
				else:
					try:
						os.mkdir(path_to_open)
						status = UsbReturnCode.UsbReturnCode_Success.value 
					except Exception as e:
						print("Error making new dir {} ~ {}".format(path_to_open, e))
						status = UsbReturnCode.UsbReturnCode_FailedTouchDir.value

			except Exception as e:
				try:
					print("Failed to touch file {}".format(path_to_open, e))
				except:
					print("Failed to touch file!!")
				status = UsbReturnCode.UsbReturnCode_FailedTouchDir.value
		else:
			status = UsbReturnCode.UsbReturnCode_FailedTouchDir.value

		return status

	def OpenDevice(self, size, io_in):
		raise notImplemented

	def ReadDevices(self, size, io_in):
		raise notImplemented

	def GetTotalDevices(self, size, io_in):
		raise notImplemented

	def GetWebDownload(self, size, io_in):
		if io_in:
			url = unpack_string(io_in, size)
			try:
				f = download_object(url)
				size = len(f)
			except Exception as e:
				try:
					print("Error downloading file from url {} ~ {}".format(url, e))
				except:
					print("Error downloading file ~ {}".format(url, e))
				return USBReturnCode.UsbReturnCode_Failure.value

			#Write length so the switch can allocate memory to receive it
			outstruct = struct.pack("<Q", size)
			self.writeUSB(outstruct)

			response = self.readUSB(0x4)
			status = struct.unpack("<l", response)

			if status == USBReturnCode.UsbReturnCode_Success.value:
				status = self._writeUSBfile(f, size, 0)

		else:
			status = USBReturnCode.UsbReturnCode_Failure.value

		return status

	#returns mode if mode was found
	def mode_poll(self):
		# try:
		print("\n\nAwaiting command...")
		try:
			io_in = self.readUSB(0x10)
		except usb.core.USBError as e:
			print("Error polling USB (Device disconnnected?) reinitializing...")
			return
		
		if io_in:
			try:
				mode = unpack_byte(io_in[0x0:0x1])
				padding = struct.unpack('<7?', io_in[0x1:0x8])[0]
				size = unpack_unsigned_long_long(io_in[0x8:0x10])
				print("Mode: {}, Size: {}".format(mode, size))
				print("Received Command {}".format(UsbMode(mode)))
			except Exception as e:
				print("Error unpacking command struct ~ {}".format(e))
				return
		else:
			print("Empty command received.")
			raise usbError

		try:
			function = self.UsbModeMap[mode]
		except Exception as e:
			try:
				print("Error selecting mode: {} ~ {}".format(mode,e))
			except:
				print("Error selecting mode! {}".format(e))
			return

		data = self.readUSB(size)
		result = function(size, data)
		if not result == -1:
			self.writeUSBReturnCode(result)


def unpack_unsigned_long_long(data):
	try:
		return struct.unpack('<Q', data)[0]
	except Exception as e:
		print("Error unpacking data to unsigned long long.\n     Data: {}\n     Error: {}".format(data, e))
		raise unpackError
def unpack_string(data, size = None):
	try:
		data = struct.unpack('<{}s'.format(size), data[0x0:size])[0]
		print("Unpacked string {}".format(data))
		return data
	except Exception as e:
		print("Error unpacking data to string.\n     Data: {}\n     Size: {}\n     Error: {}".format(data, size, e))

def unpack_byte(data):
	return struct.unpack('<B', data)[0]

def _get_endpoint(direction, cfg):
	is_ep = lambda ep: usb.util.endpoint_direction(ep.bEndpointAddress) == direction
	return usb.util.find_descriptor(cfg[(0,0)], custom_match = is_ep)

def _get_out_endpoint(cfg):
	return _get_endpoint(usb.util.ENDPOINT_OUT, cfg)

def _get_in_endpoint(cfg):
	return _get_endpoint(usb.util.ENDPOINT_IN, cfg)