import requests
import time


testletters = ''.join([str(i) for i in range(10)]) +'abcdef'
url = 'test?file=foo&signature='
recovered = '8e543ae3b5f6cde77e'

def find_next():
    times = {}
    i = 0
    while i < len(testletters):
        t1 = time.time()
        r = requests.get('http://0.0.0.0:8080/verify/'+ url + recovered + testletters[i])
        if r.status_code == 200:
            return False, testletters[i], ''
        times[time.time() - t1] = testletters[i]
        i += 1
    return True, times[max(times.keys())], (sum(times.keys()) / len(times.keys()))

if __name__ == '__main__':
    while True:
        status = find_next()
        recovered += status[1]
        print('signature recovered so far: ',recovered, '\n time: ', status[2])
        if status[0] == False:
            break

    r = requests.get('http://0.0.0.0:8080/verify/'+ url + recovered)
    print('completed. url is: ', 'http://0.0.0.0:8080/verify/'+ url + recovered)
    print('test: ', r.text)


# seems to work. could fine tune by checking that the time taken in each round
# increments by 1 time unit and correcting if not.
