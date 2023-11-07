echo -off
connect -r

for %i in 0 1 2 3 4 5 6 7 8 9 A B C D E F then
    if exist FS%i:\Sbsa.efi then
        FS%i:\Sbsa.efi
    endif
endfor
echo "Image not found"
