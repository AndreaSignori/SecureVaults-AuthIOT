def padding(elem: str, target: int) -> str:
    """
    Add at the end of the bit sequence a series of zeros until it reaches target.

    :param elem: element where to apply padding
    :param target: dimension goal for the string

    :return: padded string
    """
    diff = target - len(elem) # number of elements need to add to reach the target dimension

    padding = '0' * diff

    return elem + padding

def str_to_dict(s: str) -> dict:
    """
    Convert a string s that describe a dictionary into an actual dictionary.

    :param s: string to convert into a dictionary

    :return: dictionary described by string passed as parameter
    """
    print("Message to convert in dict:", s)
    s = s.strip("{}").replace("\'", "" ).replace('}', '') # the last replace we added because, for some reason, in some case the first strip doesn't remove '}' at the end

    return dict(item.split(": ") for item in s.split(", "))