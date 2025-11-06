import myref

print('#define u8 unsigned char')
print('u8 RS[4][8] = {')
for row in myref.RS:
    row_values = ', '.join('0x%02X' % value for value in row)
    print(f'    {{ {row_values}, }}')
print('};')
print()

def print_table(name, generator):
    print(f'u8 {name}[] = {{')
    for offset in range(0, 256, 8):
        values = ', '.join('0x%02X' % generator(i) for i in range(offset, offset + 8))
        print(f'    {values},')
    print('};')
    print()


print_table('Q0', lambda i: myref.Qpermute(i, myref.Q0))
print_table('Q1', lambda i: myref.Qpermute(i, myref.Q1))
print_table('mult5B', lambda i: myref.gfMult(0x5B, i, myref.GF_MOD))
print_table('multEF', lambda i: myref.gfMult(0xEF, i, myref.GF_MOD))

#rho = 0x01010101L
#print 'KeyConsts = ['
#for i in range(20):
#    print '    [ 0x%08XL, 0x%08XL ],' % (2*i*rho, 2*i*rho + rho)
#print ']'
#print
