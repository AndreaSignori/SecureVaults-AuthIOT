def padding(elem: str, target: int) -> str:
    """
    Add in front of the bit sequence a series of zeros until it reaches target.

    :param elem: element where to apply padding
    :param target: dimension goal for the string

    :return: padded string
    """
    diff = target - len(elem)
    padding = '0' * diff

    return padding + elem

def str_to_dict(s: str) -> dict:
    s = s.strip("{}").replace("\'", "" )

    return dict(item.split(": ") for item in s.split(", "))