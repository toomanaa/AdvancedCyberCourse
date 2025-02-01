# Function to split the plaintext into equal-length chunks (rows of the grid)
def split_len(seq, length):
    """
    Splits the plaintext into chunks of equal length.
    If the last chunk is shorter than the required length, it is padded with '_'.
    """
    s = [seq[i:i + length] for i in range(0, len(seq), length)]  # Splits into equal parts
    if len(str(s[-1])) < length:  # If the last chunk is shorter, add padding
        s[-1] = str(s[-1]).ljust(length, '_')  # Pads with '_'
    return s  # Returns the split text as a list of rows

# Function to encode (encrypt) the plaintext using the Columnar Transposition Cipher
def encode(key, plaintext):
    """
    Encrypts the plaintext using a columnar transposition method.
    The key determines the order in which columns are read.
    """
    # Create a dictionary mapping each digit in the key to its original position
    order = {int(val): num for num, val in enumerate(key)}

    ciphertext = ''  # Initialize the final encrypted text

    # Iterate through the columns in sorted order (from 1 to max column number)
    for index in sorted(order.keys()):
        for part in split_len(plaintext, len(key)):  # Get each row of the table
            ciphertext += part[order[index]]  # Append the correct column character

    return ciphertext  # Return the final encrypted text

# Define the encryption key and plaintext message
key = '43152'  # Defines the order in which columns will be rearranged
plaintext = 'TRANSPOSITION'  # The message to be encrypted

# Encrypt the plaintext using the Columnar Transposition Cipher
ciphertext = encode(key, plaintext)

# Print the original plaintext and its encrypted form
print("Plaintext  :", plaintext)
print("Ciphertext :", ciphertext)
