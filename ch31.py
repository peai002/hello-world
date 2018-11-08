import requests
import time


testletters = ''.join([str(i) for i in range(10)]) + 'abcdef'
url = 'test?file=foo&signature='
recovered = ''

def find_next(repetitions):

    avgtimes = [0]*len(testletters)

    for j in range(repetitions):
        times = []
        i = 0

        while i < len(testletters):
            t1 = time.time()
            r = requests.get('http://0.0.0.0:8080/verify/'
                             + url
                             + recovered
                             + testletters[i]
                             )

            if r.status_code == 200:
                return False, testletters[i], ''
            times += [time.time() - t1]
            i += 1

        for k in range(16):
            avgtimes[k] += times[k]

    print(avgtimes)

    return True, testletters[avgtimes.index(max(avgtimes))], sum(avgtimes)/16

if __name__ == '__main__':
    while True:
        if len(recovered) <= 10:
            reps = 3
        if len(recovered) in range(11, 21):
            reps = 5
        if len(recovered) in range(21, 31):
            reps = 10
        if len(recovered) in range(31, 41):
            reps = 15

        status = find_next(reps)
        recovered += status[1]
        print('signature recovered so far: ', recovered, '\n time: ', status[2])

        if status[0] == False:
            break

    r = requests.get('http://0.0.0.0:8080/verify/'+ url + recovered)
    print('completed. url is: ', 'http://0.0.0.0:8080/verify/'+ url + recovered)
    print('test: ', r.text)


# seems to work. could fine tune by checking that the time taken in each round
# increments by 1 time unit and correcting if not.
