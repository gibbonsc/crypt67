# crypt67

Symmetric encryption algorithm, inspired by one of the challenges in this

(2025) year's PatriotCTF ([https://competitivecyber.club/patriotctf/](https://competitivecyber.club/patriotctf/)), and

also inspired by this year's silly "[6-7](https://en.wikipedia.org/wiki/6-7_(meme))" viral meme.



The CTF challenge presented an encryption script, a ciphertext file created

by that script, and one clue consisting of a reference to a ternary operator

used in the esoteric *Malbolge* programming language. Competitors had to study

(reverse-engineer) the script and figure out how to decrypt the file. It was

my first ever successful flag earned solo in a competitive CTF, and I was so

happy to finally contribute points to my teammates in one of our

competitions!



Afterward, I continued to experiment with what I learned about arithmetic
with ternary (base 3) numerals. After hearing friends laugh about viral

growth of "six seven" slang interjections spoken in popular culture, I

thought it would be fun to make a septenary (base 7) encryption algorithm

as a block cipher, encrypting blocks of six septenary digits at a time.

"Doot Doot [6-7](https://en.wikipedia.org/wiki/6-7_(meme))!"



To Do

Right now (2025 Dec) the encryption key is hardcoded as three 7x7 matrices

derived from some interesting isograms. It would be more interesting to come

up with some way to apply an encryption key or password in an algorithm that

deterministically scrambles the matrices' entries before they are used to

encrypt and decrypt.



Regardless, this cipher is just for fun. *Don't use this cipher* for anything

you care to keep confidential! I'm certain that it's susceptible to easy

breaking through elementary cryptanalysis. Also, it uses a lot of division

operations, which are expensive. Symmetric encryption algorithms that use

fewer, carefully chosen, or no divisions tend to be faster and preferable.



