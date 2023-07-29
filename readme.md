**Leviathan Level 0:**  
`ssh leviathan0@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`leviathan0`  

For now, after login, we get a bunch of information about the server's installed packages, and additional properties.  
Let's focus on finding the password for the next level.  
if I type in `pwd`, we can clearly see that we are in our home directory, which is `/home/leviathan0`.  
As we've seen in the welcome text, all passwords are stored in /etc/somegame_pass.  
So for now, we need to look after /etc/leviathan_pass  
Let's try: `cd /etc/leviathan_pass` and `ls -l`  
As we can see, all files have a different owner, so we can't inspect them (now)  
let's go back to our home directory, by typing `cd ~`  
type `ls -la` to explore this directory.  
We can see an interesting directory, called .backup. Let's inspect it a little more.  
`cd .backup && ls`  
> bookmarks.html  

Looks like we have a file, called 'bookmarks.html'. Obviously that's not a standard unix directory and file. Let's look at what is inside:  
`nano bookmarks.html`  
It's an HTML document, with a lot of content. Let's do a quick search in it, using `grep`, maybe we could find something interesting:  
For example:  
`cat bookmarks.html | grep leviathan1`  
The password was hidden in this file!  
The password for level 1 is:  
PPIfmI1qsA

**Leviathan Level 1:**  
`ssh leviathan1@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`PPIfmI1qsA`  

After logging in, let's do a quick `ls`, to see if we have anything useful inside the home directory.  
Looks like we have something, called: 'check'  
After typing in `file ./check`  
we can see, that it is an executable file.  
Let's run this, then:  
`./check`  
It asks us for a password. Well...we dont know that.  
type something, for example: test  
It's going to say, that the password is wrong.  
Somehow we need to figure out, what could be the password that the application is asking for.  
For that, we can use the `ltrace` utility, which can display the calls of an application makes to some shared libraries.  
Let's run the following command:  
`ltrace ./check`  
It displays us a bunch of information, the first thing that we can recognize is:  
> printf("password: ")  

It displays us the command used to display the text "password:" for us. We still need to type in a password. Let's type "test" again:  
After that, we can see something interesting here:  
> strcmp("test", "sex")  

strcmp is a function, written in C. It is used to compare two strings. If the two strings are equal, this function returns 0.  
For now, the return value is not important for us. The fact however, that we can see the password that we need to type in, is important!  
Let's run the check file again, this time without ltrace, so:  
`./check`  
If we type in 'sex', we get a different promp than before. Let's type in:
`whoami`  
> leviathan2  

Cool. With this information, let's try to visit that directory, which contains all the passwords.  
`cd /etc/leviathan_pass`  
`ls`

Let's try to cat `leviathan2`  
`cat leviathan2`  

You need to exit twice this time, because you are in a completely different shell, thanks to the ./check file.

The password for level 2 is:  
mEh5PNl10e

**Leviathan Level 2:**  
`ssh leviathan2@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`mEh5PNl10e` 

After logging in, let's do a quick `ls`, to see what we need to deal with.  
`ls`  
> printfile  

Let's try to run it.  
`./printfile`

Looks like we need to give it some kind of parameter:  
> Usage: ./printfile filename  

We could try to print the password to the next level...  
`./printfile /etc/leviathan_pass/leviathan3`  
However the answer is not really promising:  
> You cant have that file...`  

So, we need to find another way. We need to find out what happens, when we run this program on a file with a correct persmission for our user. Let's go to the /tmp directory, and create a temporary diractory for us:

`cd /tmp`  
Here, create a directory with a name of your choice.  
`mkdir tempdirectoryname && cd`  
create a file here, using `touch`  
`touch test.txt`  
Great. We have an empty file. Let's write something to the file, using nano:  
`nano test.txt`  
Write whatever you want, and save it.  
Let's run the printfile application on the newly created file, using the following command:  
`~/printfile ./test.txt`  
As we've expected, the printfile prints the contents of the passed filepath.  
Let's run the printfile again, using ltrace  
`ltrace ~/printfile ./test.txt`  
It has some interesting things to note:


> access("./test.txt", 4)                                                                                                                            = 0  
> snprintf("/bin/cat ./test.txt", 511, "/bin/cat %s", "./test.txt")                                                                                  = 19  
> geteuid()                                                                                                                                          = 12002  
> geteuid()                                                                                                                                          = 12002  
> setreuid(12002, 12002)                                                                                                                             = 0  
> system("/bin/cat ./test.txt"file for testing purposes...  
>  <no return ...>  
> --- SIGCHLD (Child exited) ---  
> <... system resumed> )                                                                                                                             = 0  
> +++ exited (status 0) +++  

- access("./test.txt", 4): [access](https://man7.org/linux/man-pages/man2/access.2.html) checks the user's permissions for that file. We obviously cannot access the file containing leviathan3's password, but we can create a symlink for that.

We name the symlink `symlink_for_me`. Of course, it can be anything.  
`ln -s /etc/leviathan_pass/leviathan3 symlink_for_me`  
Now, let's try something like this:  
`~/printfile ./symlink_for_me`  
Well, looks like it's still not working, because the answer is:  
> You cant have that file...  
We need to figure out something else, but we are on the right path.  
Let's inspect the output of `ltrace ~/printfile ./test.txt` again:  


> access("./test.txt", 4)                                                                                                                            = 0  
> snprintf("/bin/cat ./test.txt", 511, "/bin/cat %s", "./test.txt")                                                                                  = 19  
> geteuid()                                                                                                                                          = 12002  
> geteuid()                                                                                                                                          = 12002  
> setreuid(12002, 12002)                                                                                                                             = 0  
> system("/bin/cat ./test.txt"file for testing purposes...  
>  <no return ...>  
> --- SIGCHLD (Child exited) ---  
> <... system resumed> )                                                                                                                             = 0  
> +++ exited (status 0) +++  

We did outsmart the access part at this point, but there is still something we miss.  
The main part of this challenge, is that how /bin/cat and access handles the passed filepath.  
Let's create a file with `touch`, like `second symlink_for_me`. The name should contain a space, and for now, the second part of the name should be name of the symlink you've created before.  
For example, if I create a file, called `second symlink_for_me`, using `touch "second symlink_for_me"` and pass it to printfile, like this:  
`~/printfile second\ symlink_for_me`  
Woah!  
Something interesting just happened:  
No more error message, that we cannot have the file, however, we've got two different messages:

> /bin/cat: second: No such file or directory  
> Q0G8j4sakn  

The first one complains about a missing file, the second one is however the password for the next level! The main reason of this behaviour, is that cat handled the name 'second symlink_for_me' as two separate files. Thanks to that, the file, named 'second' does not exists, however, the 'symlink_for_me' does exists, and it's linked to the password file. The file `second symlink_for_me` is our file, we created it, not so long ago. So, to pass this challenge, it is important to have a space in the name of our second file!  

The password for level 3 is:  
Q0G8j4sakn  

**Leviathan Level 3:**  
`ssh leviathan3@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`Q0G8j4sakn` 

By typing `ls`:  
> level 3   

We can see that we have a file, called 'level3'.
By typing `./level3`, a prompt asks for a password:  
> Enter the password>  

Type something, and it's going to say:
> bzzzzzzzzap. WRONG  

Let's use `ltrace`, then.  
`ltrace ./level3`  
> strcmp("test\n", "snlprintf\n")  

Got it!  
Type `./level3` again, with a password: `snlprintf`, and it's going to say:  
> [You've got shell]!  

Good. Let's see, what shell did we get.  
Type `whoami`, and it's going to say:  
> leviathan4  

That's very good for us, because that way we can view the contents of the file, containing the password for the next level.  
Type: `cat /etc/leviathan_pass/leviathan4`  


The password for level 4 is:  
AgvropI4OA  

**Leviathan Level 4:**  
`ssh leviathan4@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`AgvropI4OA` 

Let's type a quick `ls` to see the contents of our home dir.  
Nothing. Try `ls -la` then.  
We've got a .trash directory, which is hidden, without the 'a' flag.  
Let's look inside this directory, by typing:  
`cd .trash && ls`  
There is a file, callod bin. Let's look inside it:  
`cat bin`  
Bunch of code. Let's try to run it.  
`./bin`  
It outputs the following:  
> 01000101 01001011 01001011 01101100 01010100 01000110 00110001 01011000 01110001 01110011 00001010

It is definitely binary. Let's convert it to ascii form
It should be our password!  
The password for level 5 is:  
EKKlTF1Xqs

**Leviathan Level 5:**  
`ssh leviathan5@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`EKKlTF1Xqs` 

After typing `ls`, we can see that we have a file:  
> leviathan5  

By running it, it says:  
> Cannot find /tmp/file.log  

Well. Let's create it then.  
`touch /tmp/file.log`  
Let's run the file again, but run `ltrace`, too!  
`ltrace ./leviathan5`  
The results are the following:  

> __libc_start_main(0x8049206, 1, 0xffffdc14, 0 <unfinished ...>  
> fopen("/tmp/file.log", "r")                                                                                                                        = 0x804d1a0  
> fgetc(0x804d1a0)                                                                                                                                   = '\377'  
> feof(0x804d1a0)                                                                                                                                    = 1  
> fclose(0x804d1a0)                                                                                                                                  = 0  
> getuid()                                                                                                                                           = 12005  
> setuid(12005)                                                                                                                                      = 0  
> unlink("/tmp/file.log")                                                                                                                            = 0  
> +++ exited (status 0) +++  

So, at first, it opens the file: '/tmp/file.log', reads its content, writes it to the screen, and the removes the file. Interesting.  
Actually, there is one file in the system, the contents of which are important to us. '/etc/leviathan_pass/leviathan6'  
So, in this case, we can create a symlink that points to the needed file.  
`ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log`  
After that, rerun the given program:  
`.~/leviathan5`  
Bingo!  
The password for level 6 is:  
YZ55XPVk2l

**Leviathan Level 6:**  
`ssh leviathan6@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`YZ55XPVk2l` 

We have a file again in our home directory. This time it's called 'leviathan6'  
Let's try to run it:  
`./leviathan6`  
> usage: ./leviathan6 <4 digit code>  

We need to provide a 4 digit code for the app to perform normally.  
So, let's try it:  
`./leviathan6 1234`  
Unless you are very lucky, it's going to say:  
> Wrong`  
So, we need to automate it somehow. For that, I wrote a very simple script in bash. It looks like this:  

```
#!/bin/bash
for i in {0001..9999}; do
    echo "trying with $i"
    output=$(~/leviathan6 $i)
    if [ "$output" != "Wrong" ]; then
       echo "HERE"
    fi
done
```

This script goes from 0001 to 9999, and tries every possible number between these two.  
If the output of the script is not equals to "Wrong", then we should be okay. Let's give it a try. 
I put this script in `/tmp/yourtempdirectoryname/scriptname.sh`  
Change the directory to   
`cd /tmp/yourtempdirectoryname`  
Create an empty file:  
`touch scriptname.sh`  
Of course, you need to give it the correct permissions, so you can run the script. You can do it like this:  
`chmod +x ./scriptname.sh`  
After running the script, we can see that the script stops at 7123. It means something good for us, because the script cannot continue the execution for an unknown reason.  
Let's try this manually:  
`~/leviathan6 7123`  
It works! We've got a shell. By typing in `whoami`, it gives us the response:  
> leviathan7  
Great!  
With these permissions, we can simply print out the contens of the password file for the next level, with this command:  
`cat /etc/leviathan_pass/leviathan7`  
The password for Level 7 is:  
8GpZ5f8Hze

**Leviathan Level 7:**  
`ssh leviathan7@leviathan.labs.overthewire.org -p 2223`  
The password for this level:  
`8GpZ5f8Hze` 

This is the last level. The home directory contains a file, called CONGRATULATIONS.  
`cat CONGRATUALTIONS`  

> Well Done, you seem to have used a *nix system before, now try something more serious.  
> (Please don't post writeups, solutions or spoilers about the games on the web. Thank you!)  