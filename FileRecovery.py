#
# Use:
#
# Uses RegEx search patterns to match magic numbers for different file types,
# then writes those bytes to a new file.

import os
import re
import struct
import binascii
import argparse
import hashlib
import sys

# List of file signatures
# 
# Each item in the list uses the following format:
# [file extension, header (in hex bytes), footer (in hex bytes)]
# 
# If 'None' is in the place of the footer, this indicates that file type does not have a footer and 
# other means (such as a file size) must be used to find the end of the file.
# 
# If there are multiple types of headers/footers for a file type, the list has multiple entries

signatures = [
    ['.pdf', b'\x25\x50\x44\x46', b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0D\x25\x25\x45\x4F\x46\x0D'],
    ['.gif', b'\x47\x49\x46\x38\x37\x61', b'\x00\x00\x3B'],
    ['.gif', b'\x47\x49\x46\x38\x39\x61', b'\x00\x00\x3B'],
    ['.jpg', b'\xFF\xD8\xFF\xE0', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xE1', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xE2', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xE8', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xDB', b'\xFF\xD9'],
    ['.avi', b'\x52\x49\x46\x46....\x41\x56\x49\x20\x4C\x49\x53\x54', None],
    ['.png', b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82']
]

# 64 kb chunk size
BUF_SIZE = 65536

def main():

    # Command line parser that expects user input, which in this case I've named "disk_image"
    parser = argparse.ArgumentParser()
    parser.add_argument("disk_image")
    args = parser.parse_args()
    if args is None:
        sys.exit()

    file_name = args.disk_image

    # List of header offsets already used
    headers = []
    # List of footer offsets already used
    footers = []

    # Stores recovered files in a list so I can manipulate how they're output on the terminal.
    recovered_files = []

    # Create the directory if it does not exist
    if not os.path.exists("Recovered Files"):
        os.makedirs("Recovered Files")

    # Open the file name from the command line argument and reads the file 'r' as bytes in binary mode 'b'.
    file = open(file_name, "rb")
    b = file.read()
    file.close()

    # Skip flags that are used to ensure only valid files are carved
    # True = offsets not valid
    # False = offsets are valid
    head_skip = False
    foot_skip = False
    pdf_skip = False

    # Iterates through each of the file types in the signatures list
    for sig in signatures:
    
        # Compile a regex pattern using the hex bytes for the header
        reg_head = re.compile(sig[1])

        # Iterates through all RegEx matches found for the header pattern
        for match_head in reg_head.finditer(b):
        
            # The offset is the start of the pattern match
            offset = match_head.start()
            head_skip = False

            # If we have already carved a file using this header offset, then skip it
            if offset in headers:
                head_skip = True

            # Get the contents of the file from the header offset to the end of file
            start = b[offset:]
            
            # Initialize 'end' to avoid 'ReferencedBeforeAssignment' Error.
            end = None  

            # If the file type is a pdf, the next pdf header (if any), must be found so that the correct EOF is used
            next_offset = 0
            if sig[0] == '.pdf' and head_skip is False:
            
                # Finds offset of next header match
                for match in reg_head.finditer(b[offset+1:]):
                    next_offset = match.start() + offset
                    break

            # We only need to find a footer if the header is valid, which means the head_skip flag must be false
            if head_skip is False:
                # If this file type has a footer value, then find the footer
                if sig[2] is not None:
                
                    # Compile a regex pattern using the hex bytes for the footer
                    reg_foot = re.compile(sig[2])
                    
                    # Iterate through all matches for the footer pattern searching forward, starting from the current header offset.
                    for match_foot in reg_foot.finditer(start):
                    
                        # The end offset is the end of the footer match
                        end = match_foot.end()
                        
                        # Add the header offset to get the true offset within the image
                        end += offset

                        # Determines if the pdf footer value is valid
                        pdf_skip = False
                        
                        # Finds next footer offset
                        next_end = 0

                        # Since pdf's can have multiple EOFs, the end offset must be verified.
                        # This is achieved by looking for the next pdf header starting offset.
                        # If there are no more pdf headers, then the last footer in the iterator will be used.
                        if sig[0] == '.pdf':
                        
                            # Finds the next match for the footer pattern, searching from the current footer offset and forward.
                            for match in reg_foot.finditer(b[end:]):
                                next_end = match.start() + end
                                break
                                
                            # If next_offset is not 0, then there is another pdf header in the file.
                            if next_offset != 0:
                            
                                # If the current footer offset is greater than the next pdf header start, the offset must be invalid.
                                # So, the pdf_skip flag is set to True and the footer match loop is exited.
                                if end > next_offset:
                                    pdf_skip = True
                                    break
                                    
                                # If there is another footer match, check if the next footer is past the start of the next pdf header.
                                # If the next footer match is past the start of the next pdf header, then the current footer offset must be a valid EOF.
                                # So, exit the footer match for loop.
                                elif next_end != 0:
                                    if next_end > next_offset:
                                        break
                        # If the file type is not pdf, then only the first footer match is needed.
                        # So, exit the footer match for loop.
                        else:
                            break
                # Since the avi file type does not have a footer, the file size must be calculated
                else:
                    if sig[0] == '.avi':
                    
                        # avi file size is located 4 bytes from start of file
                        head = 4
                        
                    # Add the offset for the file size to start of header match
                    size_start = offset + head

		    # File size is 4 bytes
                    # Read each byte individually, convert to hex, chop of the '0x', pad with zeroes
                    # so there is always atleast 2 hex numbers per byte.
                    # Convert the hex numbers to a string and concatenate the strings together.
                    size = str(hex(b[size_start])[2:].zfill(2)) + str(hex(b[size_start+1])[2:]).zfill(2) + str(hex(b[size_start+2])[2:].zfill(2)) + str(hex(b[size_start+3])[2:]).zfill(2)
                    
                    # Convert the hex string to bytes
                    size_b = binascii.unhexlify(size)
                    
                    # Convert the little endian bytes to a long.
                    # The '<' indicates little endian, and the 'l' indicates a long.
                    long_size = struct.unpack('<l', size_b)
                    
                    # Add the file size to the header offset
                    end = offset + long_size[0]

                    # For avi files, 8 bytes must be added to account for the header + file size bytes.
                    if sig[0] == '.avi':
                        end += 8

            # If we have already carved a file using this footer offset,
            # then skip this offset (since it can't be valid)
            foot_skip = False
            if end is not None and end in footers:  # Ensure 'end' is not None
                foot_skip = True

            # If all skip flags are False, the offsets are valid, so carve the file, find the hash, and print file info.
            if not (head_skip or foot_skip or pdf_skip):
            
                # Add the header and footer offsets to their lists
                headers.append(offset)
                footers.append(end)

		# Prevents running into the 'ReferencedBeforeAssignment' error.
                if end is not None:
                
                    # Write the data from the header offset to the footer offset to a new file
                    newfile = b[offset:end]
                    
                    # File name is controlled by the file counter and the file extension specified in the signature.
                    filename = f'file{len(recovered_files) + 1}{sig[0]}'
                    name = os.path.join("Recovered Files", filename)
                    with open(name, "wb") as file_out:
                        file_out.write(newfile)

		    # Get sha256 hash of file
                    file_hash = sha256_hash(name)

		    # Store file information in a list to print after all files have been identified and recovered.
                    recovered_files.append({
                    
                        # Store only the filename, not the path
                        "name": filename,  
                        
                        #Removes '0x' and pad the result to 6 characters or 3 bytes
                        "start_offset_hex": hex(offset)[2:].zfill(6),
                        "start_offset_dec": offset,
                        "end_offset_hex": hex(end)[2:].zfill(6),
                        "end_offset_dec": end,
                        "sha256_hash": file_hash
                    })
		
		# Print recovered file information
                else:
                    print(f"Unable to find end for {sig[0]} at offset {hex(offset)}")

    print(f"\nThe disk image contains {len(recovered_files)} files.")

    for file_info in recovered_files:
        print(f"\nFile Name:     {file_info['name']}")
        print(f"Start Offset:  0x{file_info['start_offset_hex']} (decimal: {file_info['start_offset_dec']})")
        print(f"End Offset:    0x{file_info['end_offset_hex']} (decimal: {file_info['end_offset_dec']})")
        print(f"SHA-256 Hash:  {file_info['sha256_hash']}")
        
    print(f"\nThe disk image contains {len(recovered_files)} files.\n")

# Scans through the file and generates the SHA-256 hash in chunks of 64K using the hashlib function.
def sha256_hash(file):
    with open(file, "rb") as hashfile:
        data = hashfile.read(BUF_SIZE)
        hasher = hashlib.sha256(data)
        while data:
            data = hashfile.read(BUF_SIZE)
            hasher.update(data)
    return hasher.hexdigest()

if __name__ == "__main__":
    main()

