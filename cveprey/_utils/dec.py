import time, os

def timeTaken(function):
    '''
    Calculates the time taken by a function
    '''
    def calc(*args, **kwargs):
        start = time.time()
        ret = function(*args, **kwargs)
        end = time.time()
        print("Total time calculated in %s : %.2f" % (function.__name__, end - start), "sec")
        return ret

    return calc

def cache(func):
    '''
    Caches the data for a function
    '''
    def process_cache(*args, **kwargs):
        ret = func(*args, **kwargs)
        try:
            os.mkdir('./cache')
        except FileExistsError:
            pass
        fp = open('./cache/'+func.__name__+'.chc', 'wt')
        fp.write(ret)
        fp.close()
        return ret
    
    return process_cache

