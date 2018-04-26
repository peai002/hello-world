<h1> Cryptopals </h1>


These are solutions that I have written to the cryptopals crypto challenges (available at the <a href="cryptopals.com"> cryptopals website</a>.)

The solutions are written in Python. When I started writing, I had little to no knowledge of python and programming. 
This project was a way for me to learn to code and to learn a bit about cryptography. I've really enjoyed the process so far. As I've progressed I've been learning about some more advanced python techniques like exception handling and classes. 

I'm in two minds about whether to go back and edit earlier code to make it look better. I think it would be good practice and it would make the project feel more complete. 
However, on the other hand, I'm quite lazy, so I think I'll try and incorporate more sophistication as I go along. 

<h1>Overview </h1>


<h2>Challenge 14 </h3>

<h3>Problem: </h3>

We are given an encryption oracle that takes an input <code>string</code>, and then outputs:

<code>AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)</code>

The aim is to decode those target bytes. The main difficulty here is that the random-prefix is not fixed-length. 

Of course, seeing as I wrote the code for the encryption oracle myself I could have chosen to fix the length... that would have made things too easy though! 
I did allow myself one simplification: random-prefix is between zero and sixteen bytes. The length of the random-prefix has to have some upper bound, so this seems reasonable. I think it would still be possible to find a solution even with longer random-prefixes -- after all, only the last (partial-)block of the prefix matters. 

<h3>Solution: </h3>

<h4>Step 1: </h4>

The key insight was to write a function that allows us to encrypt a given block. Although we are using ECB, because of the random-prefix we can't be sure where our block ends up. 




