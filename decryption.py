
def decrypt_rot13(string):
    lower_letters = [chr(x) for x in range(97, 123)];
    upper_letters = [chr(x) for x in range(65, 91)];
    decrypt_string = ""

    for char in string:
        if char.isupper():
            original_index = upper_letters.index(char)
            new_index = (original_index + 13) % len(upper_letters)
            decrypt_string += upper_letters[new_index]
        elif char.islower():
            original_index = lower_letters.index(char)
            new_index = (original_index + 13) % len(lower_letters)
            decrypt_string += lower_letters[new_index]
        else:
            decrypt_string += char
    return decrypt_string