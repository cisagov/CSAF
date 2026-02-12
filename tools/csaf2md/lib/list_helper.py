def flatten(list_of_lists:list):
    '''Flatten
    Condenses a list of lists into a single dimensional list.

    Args:
        list_of_lists:list 
    Returns:
        condense:list
    '''
    condense = []
    for i in list_of_lists:
        if isinstance(i,list): 
            condense.extend(flatten(i))
        else: 
            condense.append(i)
    return condense
