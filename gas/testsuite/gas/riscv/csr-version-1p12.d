#as: -march=rv64i_zicsr -mcsr-check -mpriv-spec=1.12
#source: csr.s
#warning_output: csr-version-1p12.l
#objdump: -d -Mpriv-spec=1.12

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <.text>:
[ 	]+[0-9a-f]+:[ 	]+00002573[ 	]+csrr[ 	]+a0,ustatus
[ 	]+[0-9a-f]+:[ 	]+00059073[ 	]+csrw[ 	]+ustatus,a1
[ 	]+[0-9a-f]+:[ 	]+00402573[ 	]+csrr[ 	]+a0,uie
[ 	]+[0-9a-f]+:[ 	]+00459073[ 	]+csrw[ 	]+uie,a1
[ 	]+[0-9a-f]+:[ 	]+00502573[ 	]+csrr[ 	]+a0,utvec
[ 	]+[0-9a-f]+:[ 	]+00559073[ 	]+csrw[ 	]+utvec,a1
[ 	]+[0-9a-f]+:[ 	]+04002573[ 	]+csrr[ 	]+a0,uscratch
[ 	]+[0-9a-f]+:[ 	]+04059073[ 	]+csrw[ 	]+uscratch,a1
[ 	]+[0-9a-f]+:[ 	]+04102573[ 	]+csrr[ 	]+a0,uepc
[ 	]+[0-9a-f]+:[ 	]+04159073[ 	]+csrw[ 	]+uepc,a1
[ 	]+[0-9a-f]+:[ 	]+04202573[ 	]+csrr[ 	]+a0,ucause
[ 	]+[0-9a-f]+:[ 	]+04259073[ 	]+csrw[ 	]+ucause,a1
[ 	]+[0-9a-f]+:[ 	]+04302573[ 	]+csrr[ 	]+a0,utval
[ 	]+[0-9a-f]+:[ 	]+04359073[ 	]+csrw[ 	]+utval,a1
[ 	]+[0-9a-f]+:[ 	]+04402573[ 	]+csrr[ 	]+a0,uip
[ 	]+[0-9a-f]+:[ 	]+04459073[ 	]+csrw[ 	]+uip,a1
[ 	]+[0-9a-f]+:[ 	]+c0002573[ 	]+rdcycle[ 	]+a0
[ 	]+[0-9a-f]+:[ 	]+c0059073[ 	]+csrw[ 	]+cycle,a1
[ 	]+[0-9a-f]+:[ 	]+c0102573[ 	]+rdtime[ 	]+a0
[ 	]+[0-9a-f]+:[ 	]+c0159073[ 	]+csrw[ 	]+time,a1
[ 	]+[0-9a-f]+:[ 	]+c0202573[ 	]+rdinstret[ 	]+a0
[ 	]+[0-9a-f]+:[ 	]+c0259073[ 	]+csrw[ 	]+instret,a1
[ 	]+[0-9a-f]+:[ 	]+c0302573[ 	]+csrr[ 	]+a0,hpmcounter3
[ 	]+[0-9a-f]+:[ 	]+c0359073[ 	]+csrw[ 	]+hpmcounter3,a1
[ 	]+[0-9a-f]+:[ 	]+c0402573[ 	]+csrr[ 	]+a0,hpmcounter4
[ 	]+[0-9a-f]+:[ 	]+c0459073[ 	]+csrw[ 	]+hpmcounter4,a1
[ 	]+[0-9a-f]+:[ 	]+c0502573[ 	]+csrr[ 	]+a0,hpmcounter5
[ 	]+[0-9a-f]+:[ 	]+c0559073[ 	]+csrw[ 	]+hpmcounter5,a1
[ 	]+[0-9a-f]+:[ 	]+c0602573[ 	]+csrr[ 	]+a0,hpmcounter6
[ 	]+[0-9a-f]+:[ 	]+c0659073[ 	]+csrw[ 	]+hpmcounter6,a1
[ 	]+[0-9a-f]+:[ 	]+c0702573[ 	]+csrr[ 	]+a0,hpmcounter7
[ 	]+[0-9a-f]+:[ 	]+c0759073[ 	]+csrw[ 	]+hpmcounter7,a1
[ 	]+[0-9a-f]+:[ 	]+c0802573[ 	]+csrr[ 	]+a0,hpmcounter8
[ 	]+[0-9a-f]+:[ 	]+c0859073[ 	]+csrw[ 	]+hpmcounter8,a1
[ 	]+[0-9a-f]+:[ 	]+c0902573[ 	]+csrr[ 	]+a0,hpmcounter9
[ 	]+[0-9a-f]+:[ 	]+c0959073[ 	]+csrw[ 	]+hpmcounter9,a1
[ 	]+[0-9a-f]+:[ 	]+c0a02573[ 	]+csrr[ 	]+a0,hpmcounter10
[ 	]+[0-9a-f]+:[ 	]+c0a59073[ 	]+csrw[ 	]+hpmcounter10,a1
[ 	]+[0-9a-f]+:[ 	]+c0b02573[ 	]+csrr[ 	]+a0,hpmcounter11
[ 	]+[0-9a-f]+:[ 	]+c0b59073[ 	]+csrw[ 	]+hpmcounter11,a1
[ 	]+[0-9a-f]+:[ 	]+c0c02573[ 	]+csrr[ 	]+a0,hpmcounter12
[ 	]+[0-9a-f]+:[ 	]+c0c59073[ 	]+csrw[ 	]+hpmcounter12,a1
[ 	]+[0-9a-f]+:[ 	]+c0d02573[ 	]+csrr[ 	]+a0,hpmcounter13
[ 	]+[0-9a-f]+:[ 	]+c0d59073[ 	]+csrw[ 	]+hpmcounter13,a1
[ 	]+[0-9a-f]+:[ 	]+c0e02573[ 	]+csrr[ 	]+a0,hpmcounter14
[ 	]+[0-9a-f]+:[ 	]+c0e59073[ 	]+csrw[ 	]+hpmcounter14,a1
[ 	]+[0-9a-f]+:[ 	]+c0f02573[ 	]+csrr[ 	]+a0,hpmcounter15
[ 	]+[0-9a-f]+:[ 	]+c0f59073[ 	]+csrw[ 	]+hpmcounter15,a1
[ 	]+[0-9a-f]+:[ 	]+c1002573[ 	]+csrr[ 	]+a0,hpmcounter16
[ 	]+[0-9a-f]+:[ 	]+c1059073[ 	]+csrw[ 	]+hpmcounter16,a1
[ 	]+[0-9a-f]+:[ 	]+c1102573[ 	]+csrr[ 	]+a0,hpmcounter17
[ 	]+[0-9a-f]+:[ 	]+c1159073[ 	]+csrw[ 	]+hpmcounter17,a1
[ 	]+[0-9a-f]+:[ 	]+c1202573[ 	]+csrr[ 	]+a0,hpmcounter18
[ 	]+[0-9a-f]+:[ 	]+c1259073[ 	]+csrw[ 	]+hpmcounter18,a1
[ 	]+[0-9a-f]+:[ 	]+c1302573[ 	]+csrr[ 	]+a0,hpmcounter19
[ 	]+[0-9a-f]+:[ 	]+c1359073[ 	]+csrw[ 	]+hpmcounter19,a1
[ 	]+[0-9a-f]+:[ 	]+c1402573[ 	]+csrr[ 	]+a0,hpmcounter20
[ 	]+[0-9a-f]+:[ 	]+c1459073[ 	]+csrw[ 	]+hpmcounter20,a1
[ 	]+[0-9a-f]+:[ 	]+c1502573[ 	]+csrr[ 	]+a0,hpmcounter21
[ 	]+[0-9a-f]+:[ 	]+c1559073[ 	]+csrw[ 	]+hpmcounter21,a1
[ 	]+[0-9a-f]+:[ 	]+c1602573[ 	]+csrr[ 	]+a0,hpmcounter22
[ 	]+[0-9a-f]+:[ 	]+c1659073[ 	]+csrw[ 	]+hpmcounter22,a1
[ 	]+[0-9a-f]+:[ 	]+c1702573[ 	]+csrr[ 	]+a0,hpmcounter23
[ 	]+[0-9a-f]+:[ 	]+c1759073[ 	]+csrw[ 	]+hpmcounter23,a1
[ 	]+[0-9a-f]+:[ 	]+c1802573[ 	]+csrr[ 	]+a0,hpmcounter24
[ 	]+[0-9a-f]+:[ 	]+c1859073[ 	]+csrw[ 	]+hpmcounter24,a1
[ 	]+[0-9a-f]+:[ 	]+c1902573[ 	]+csrr[ 	]+a0,hpmcounter25
[ 	]+[0-9a-f]+:[ 	]+c1959073[ 	]+csrw[ 	]+hpmcounter25,a1
[ 	]+[0-9a-f]+:[ 	]+c1a02573[ 	]+csrr[ 	]+a0,hpmcounter26
[ 	]+[0-9a-f]+:[ 	]+c1a59073[ 	]+csrw[ 	]+hpmcounter26,a1
[ 	]+[0-9a-f]+:[ 	]+c1b02573[ 	]+csrr[ 	]+a0,hpmcounter27
[ 	]+[0-9a-f]+:[ 	]+c1b59073[ 	]+csrw[ 	]+hpmcounter27,a1
[ 	]+[0-9a-f]+:[ 	]+c1c02573[ 	]+csrr[ 	]+a0,hpmcounter28
[ 	]+[0-9a-f]+:[ 	]+c1c59073[ 	]+csrw[ 	]+hpmcounter28,a1
[ 	]+[0-9a-f]+:[ 	]+c1d02573[ 	]+csrr[ 	]+a0,hpmcounter29
[ 	]+[0-9a-f]+:[ 	]+c1d59073[ 	]+csrw[ 	]+hpmcounter29,a1
[ 	]+[0-9a-f]+:[ 	]+c1e02573[ 	]+csrr[ 	]+a0,hpmcounter30
[ 	]+[0-9a-f]+:[ 	]+c1e59073[ 	]+csrw[ 	]+hpmcounter30,a1
[ 	]+[0-9a-f]+:[ 	]+c1f02573[ 	]+csrr[ 	]+a0,hpmcounter31
[ 	]+[0-9a-f]+:[ 	]+c1f59073[ 	]+csrw[ 	]+hpmcounter31,a1
[ 	]+[0-9a-f]+:[ 	]+c8002573[ 	]+csrr[ 	]+a0,cycleh
[ 	]+[0-9a-f]+:[ 	]+c8059073[ 	]+csrw[ 	]+cycleh,a1
[ 	]+[0-9a-f]+:[ 	]+c8102573[ 	]+csrr[ 	]+a0,timeh
[ 	]+[0-9a-f]+:[ 	]+c8159073[ 	]+csrw[ 	]+timeh,a1
[ 	]+[0-9a-f]+:[ 	]+c8202573[ 	]+csrr[ 	]+a0,instreth
[ 	]+[0-9a-f]+:[ 	]+c8259073[ 	]+csrw[ 	]+instreth,a1
[ 	]+[0-9a-f]+:[ 	]+c8302573[ 	]+csrr[ 	]+a0,hpmcounter3h
[ 	]+[0-9a-f]+:[ 	]+c8359073[ 	]+csrw[ 	]+hpmcounter3h,a1
[ 	]+[0-9a-f]+:[ 	]+c8402573[ 	]+csrr[ 	]+a0,hpmcounter4h
[ 	]+[0-9a-f]+:[ 	]+c8459073[ 	]+csrw[ 	]+hpmcounter4h,a1
[ 	]+[0-9a-f]+:[ 	]+c8502573[ 	]+csrr[ 	]+a0,hpmcounter5h
[ 	]+[0-9a-f]+:[ 	]+c8559073[ 	]+csrw[ 	]+hpmcounter5h,a1
[ 	]+[0-9a-f]+:[ 	]+c8602573[ 	]+csrr[ 	]+a0,hpmcounter6h
[ 	]+[0-9a-f]+:[ 	]+c8659073[ 	]+csrw[ 	]+hpmcounter6h,a1
[ 	]+[0-9a-f]+:[ 	]+c8702573[ 	]+csrr[ 	]+a0,hpmcounter7h
[ 	]+[0-9a-f]+:[ 	]+c8759073[ 	]+csrw[ 	]+hpmcounter7h,a1
[ 	]+[0-9a-f]+:[ 	]+c8802573[ 	]+csrr[ 	]+a0,hpmcounter8h
[ 	]+[0-9a-f]+:[ 	]+c8859073[ 	]+csrw[ 	]+hpmcounter8h,a1
[ 	]+[0-9a-f]+:[ 	]+c8902573[ 	]+csrr[ 	]+a0,hpmcounter9h
[ 	]+[0-9a-f]+:[ 	]+c8959073[ 	]+csrw[ 	]+hpmcounter9h,a1
[ 	]+[0-9a-f]+:[ 	]+c8a02573[ 	]+csrr[ 	]+a0,hpmcounter10h
[ 	]+[0-9a-f]+:[ 	]+c8a59073[ 	]+csrw[ 	]+hpmcounter10h,a1
[ 	]+[0-9a-f]+:[ 	]+c8b02573[ 	]+csrr[ 	]+a0,hpmcounter11h
[ 	]+[0-9a-f]+:[ 	]+c8b59073[ 	]+csrw[ 	]+hpmcounter11h,a1
[ 	]+[0-9a-f]+:[ 	]+c8c02573[ 	]+csrr[ 	]+a0,hpmcounter12h
[ 	]+[0-9a-f]+:[ 	]+c8c59073[ 	]+csrw[ 	]+hpmcounter12h,a1
[ 	]+[0-9a-f]+:[ 	]+c8d02573[ 	]+csrr[ 	]+a0,hpmcounter13h
[ 	]+[0-9a-f]+:[ 	]+c8d59073[ 	]+csrw[ 	]+hpmcounter13h,a1
[ 	]+[0-9a-f]+:[ 	]+c8e02573[ 	]+csrr[ 	]+a0,hpmcounter14h
[ 	]+[0-9a-f]+:[ 	]+c8e59073[ 	]+csrw[ 	]+hpmcounter14h,a1
[ 	]+[0-9a-f]+:[ 	]+c8f02573[ 	]+csrr[ 	]+a0,hpmcounter15h
[ 	]+[0-9a-f]+:[ 	]+c8f59073[ 	]+csrw[ 	]+hpmcounter15h,a1
[ 	]+[0-9a-f]+:[ 	]+c9002573[ 	]+csrr[ 	]+a0,hpmcounter16h
[ 	]+[0-9a-f]+:[ 	]+c9059073[ 	]+csrw[ 	]+hpmcounter16h,a1
[ 	]+[0-9a-f]+:[ 	]+c9102573[ 	]+csrr[ 	]+a0,hpmcounter17h
[ 	]+[0-9a-f]+:[ 	]+c9159073[ 	]+csrw[ 	]+hpmcounter17h,a1
[ 	]+[0-9a-f]+:[ 	]+c9202573[ 	]+csrr[ 	]+a0,hpmcounter18h
[ 	]+[0-9a-f]+:[ 	]+c9259073[ 	]+csrw[ 	]+hpmcounter18h,a1
[ 	]+[0-9a-f]+:[ 	]+c9302573[ 	]+csrr[ 	]+a0,hpmcounter19h
[ 	]+[0-9a-f]+:[ 	]+c9359073[ 	]+csrw[ 	]+hpmcounter19h,a1
[ 	]+[0-9a-f]+:[ 	]+c9402573[ 	]+csrr[ 	]+a0,hpmcounter20h
[ 	]+[0-9a-f]+:[ 	]+c9459073[ 	]+csrw[ 	]+hpmcounter20h,a1
[ 	]+[0-9a-f]+:[ 	]+c9502573[ 	]+csrr[ 	]+a0,hpmcounter21h
[ 	]+[0-9a-f]+:[ 	]+c9559073[ 	]+csrw[ 	]+hpmcounter21h,a1
[ 	]+[0-9a-f]+:[ 	]+c9602573[ 	]+csrr[ 	]+a0,hpmcounter22h
[ 	]+[0-9a-f]+:[ 	]+c9659073[ 	]+csrw[ 	]+hpmcounter22h,a1
[ 	]+[0-9a-f]+:[ 	]+c9702573[ 	]+csrr[ 	]+a0,hpmcounter23h
[ 	]+[0-9a-f]+:[ 	]+c9759073[ 	]+csrw[ 	]+hpmcounter23h,a1
[ 	]+[0-9a-f]+:[ 	]+c9802573[ 	]+csrr[ 	]+a0,hpmcounter24h
[ 	]+[0-9a-f]+:[ 	]+c9859073[ 	]+csrw[ 	]+hpmcounter24h,a1
[ 	]+[0-9a-f]+:[ 	]+c9902573[ 	]+csrr[ 	]+a0,hpmcounter25h
[ 	]+[0-9a-f]+:[ 	]+c9959073[ 	]+csrw[ 	]+hpmcounter25h,a1
[ 	]+[0-9a-f]+:[ 	]+c9a02573[ 	]+csrr[ 	]+a0,hpmcounter26h
[ 	]+[0-9a-f]+:[ 	]+c9a59073[ 	]+csrw[ 	]+hpmcounter26h,a1
[ 	]+[0-9a-f]+:[ 	]+c9b02573[ 	]+csrr[ 	]+a0,hpmcounter27h
[ 	]+[0-9a-f]+:[ 	]+c9b59073[ 	]+csrw[ 	]+hpmcounter27h,a1
[ 	]+[0-9a-f]+:[ 	]+c9c02573[ 	]+csrr[ 	]+a0,hpmcounter28h
[ 	]+[0-9a-f]+:[ 	]+c9c59073[ 	]+csrw[ 	]+hpmcounter28h,a1
[ 	]+[0-9a-f]+:[ 	]+c9d02573[ 	]+csrr[ 	]+a0,hpmcounter29h
[ 	]+[0-9a-f]+:[ 	]+c9d59073[ 	]+csrw[ 	]+hpmcounter29h,a1
[ 	]+[0-9a-f]+:[ 	]+c9e02573[ 	]+csrr[ 	]+a0,hpmcounter30h
[ 	]+[0-9a-f]+:[ 	]+c9e59073[ 	]+csrw[ 	]+hpmcounter30h,a1
[ 	]+[0-9a-f]+:[ 	]+c9f02573[ 	]+csrr[ 	]+a0,hpmcounter31h
[ 	]+[0-9a-f]+:[ 	]+c9f59073[ 	]+csrw[ 	]+hpmcounter31h,a1
[ 	]+[0-9a-f]+:[ 	]+10002573[ 	]+csrr[ 	]+a0,sstatus
[ 	]+[0-9a-f]+:[ 	]+10059073[ 	]+csrw[ 	]+sstatus,a1
[ 	]+[0-9a-f]+:[ 	]+10202573[ 	]+csrr[ 	]+a0,sedeleg
[ 	]+[0-9a-f]+:[ 	]+10259073[ 	]+csrw[ 	]+sedeleg,a1
[ 	]+[0-9a-f]+:[ 	]+10302573[ 	]+csrr[ 	]+a0,sideleg
[ 	]+[0-9a-f]+:[ 	]+10359073[ 	]+csrw[ 	]+sideleg,a1
[ 	]+[0-9a-f]+:[ 	]+10402573[ 	]+csrr[ 	]+a0,sie
[ 	]+[0-9a-f]+:[ 	]+10459073[ 	]+csrw[ 	]+sie,a1
[ 	]+[0-9a-f]+:[ 	]+10502573[ 	]+csrr[ 	]+a0,stvec
[ 	]+[0-9a-f]+:[ 	]+10559073[ 	]+csrw[ 	]+stvec,a1
[ 	]+[0-9a-f]+:[ 	]+10602573[ 	]+csrr[ 	]+a0,scounteren
[ 	]+[0-9a-f]+:[ 	]+10659073[ 	]+csrw[ 	]+scounteren,a1
[ 	]+[0-9a-f]+:[ 	]+14002573[ 	]+csrr[ 	]+a0,sscratch
[ 	]+[0-9a-f]+:[ 	]+14059073[ 	]+csrw[ 	]+sscratch,a1
[ 	]+[0-9a-f]+:[ 	]+14102573[ 	]+csrr[ 	]+a0,sepc
[ 	]+[0-9a-f]+:[ 	]+14159073[ 	]+csrw[ 	]+sepc,a1
[ 	]+[0-9a-f]+:[ 	]+14202573[ 	]+csrr[ 	]+a0,scause
[ 	]+[0-9a-f]+:[ 	]+14259073[ 	]+csrw[ 	]+scause,a1
[ 	]+[0-9a-f]+:[ 	]+14302573[ 	]+csrr[ 	]+a0,stval
[ 	]+[0-9a-f]+:[ 	]+14359073[ 	]+csrw[ 	]+stval,a1
[ 	]+[0-9a-f]+:[ 	]+14402573[ 	]+csrr[ 	]+a0,sip
[ 	]+[0-9a-f]+:[ 	]+14459073[ 	]+csrw[ 	]+sip,a1
[ 	]+[0-9a-f]+:[ 	]+18002573[ 	]+csrr[ 	]+a0,satp
[ 	]+[0-9a-f]+:[ 	]+18059073[ 	]+csrw[ 	]+satp,a1
[ 	]+[0-9a-f]+:[ 	]+f1102573[ 	]+csrr[ 	]+a0,mvendorid
[ 	]+[0-9a-f]+:[ 	]+f1159073[ 	]+csrw[ 	]+mvendorid,a1
[ 	]+[0-9a-f]+:[ 	]+f1202573[ 	]+csrr[ 	]+a0,marchid
[ 	]+[0-9a-f]+:[ 	]+f1259073[ 	]+csrw[ 	]+marchid,a1
[ 	]+[0-9a-f]+:[ 	]+f1302573[ 	]+csrr[ 	]+a0,mimpid
[ 	]+[0-9a-f]+:[ 	]+f1359073[ 	]+csrw[ 	]+mimpid,a1
[ 	]+[0-9a-f]+:[ 	]+f1402573[ 	]+csrr[ 	]+a0,mhartid
[ 	]+[0-9a-f]+:[ 	]+f1459073[ 	]+csrw[ 	]+mhartid,a1
[ 	]+[0-9a-f]+:[ 	]+30002573[ 	]+csrr[ 	]+a0,mstatus
[ 	]+[0-9a-f]+:[ 	]+30059073[ 	]+csrw[ 	]+mstatus,a1
[ 	]+[0-9a-f]+:[ 	]+30102573[ 	]+csrr[ 	]+a0,misa
[ 	]+[0-9a-f]+:[ 	]+30159073[ 	]+csrw[ 	]+misa,a1
[ 	]+[0-9a-f]+:[ 	]+30202573[ 	]+csrr[ 	]+a0,medeleg
[ 	]+[0-9a-f]+:[ 	]+30259073[ 	]+csrw[ 	]+medeleg,a1
[ 	]+[0-9a-f]+:[ 	]+30302573[ 	]+csrr[ 	]+a0,mideleg
[ 	]+[0-9a-f]+:[ 	]+30359073[ 	]+csrw[ 	]+mideleg,a1
[ 	]+[0-9a-f]+:[ 	]+30402573[ 	]+csrr[ 	]+a0,mie
[ 	]+[0-9a-f]+:[ 	]+30459073[ 	]+csrw[ 	]+mie,a1
[ 	]+[0-9a-f]+:[ 	]+30502573[ 	]+csrr[ 	]+a0,mtvec
[ 	]+[0-9a-f]+:[ 	]+30559073[ 	]+csrw[ 	]+mtvec,a1
[ 	]+[0-9a-f]+:[ 	]+30602573[ 	]+csrr[ 	]+a0,mcounteren
[ 	]+[0-9a-f]+:[ 	]+30659073[ 	]+csrw[ 	]+mcounteren,a1
[ 	]+[0-9a-f]+:[ 	]+34002573[ 	]+csrr[ 	]+a0,mscratch
[ 	]+[0-9a-f]+:[ 	]+34059073[ 	]+csrw[ 	]+mscratch,a1
[ 	]+[0-9a-f]+:[ 	]+34102573[ 	]+csrr[ 	]+a0,mepc
[ 	]+[0-9a-f]+:[ 	]+34159073[ 	]+csrw[ 	]+mepc,a1
[ 	]+[0-9a-f]+:[ 	]+34202573[ 	]+csrr[ 	]+a0,mcause
[ 	]+[0-9a-f]+:[ 	]+34259073[ 	]+csrw[ 	]+mcause,a1
[ 	]+[0-9a-f]+:[ 	]+34302573[ 	]+csrr[ 	]+a0,mtval
[ 	]+[0-9a-f]+:[ 	]+34359073[ 	]+csrw[ 	]+mtval,a1
[ 	]+[0-9a-f]+:[ 	]+34402573[ 	]+csrr[ 	]+a0,mip
[ 	]+[0-9a-f]+:[ 	]+34459073[ 	]+csrw[ 	]+mip,a1
[ 	]+[0-9a-f]+:[ 	]+3a002573[ 	]+csrr[ 	]+a0,pmpcfg0
[ 	]+[0-9a-f]+:[ 	]+3a059073[ 	]+csrw[ 	]+pmpcfg0,a1
[ 	]+[0-9a-f]+:[ 	]+3a102573[ 	]+csrr[ 	]+a0,pmpcfg1
[ 	]+[0-9a-f]+:[ 	]+3a159073[ 	]+csrw[ 	]+pmpcfg1,a1
[ 	]+[0-9a-f]+:[ 	]+3a202573[ 	]+csrr[ 	]+a0,pmpcfg2
[ 	]+[0-9a-f]+:[ 	]+3a259073[ 	]+csrw[ 	]+pmpcfg2,a1
[ 	]+[0-9a-f]+:[ 	]+3a302573[ 	]+csrr[ 	]+a0,pmpcfg3
[ 	]+[0-9a-f]+:[ 	]+3a359073[ 	]+csrw[ 	]+pmpcfg3,a1
[ 	]+[0-9a-f]+:[ 	]+3b002573[ 	]+csrr[ 	]+a0,pmpaddr0
[ 	]+[0-9a-f]+:[ 	]+3b059073[ 	]+csrw[ 	]+pmpaddr0,a1
[ 	]+[0-9a-f]+:[ 	]+3b102573[ 	]+csrr[ 	]+a0,pmpaddr1
[ 	]+[0-9a-f]+:[ 	]+3b159073[ 	]+csrw[ 	]+pmpaddr1,a1
[ 	]+[0-9a-f]+:[ 	]+3b202573[ 	]+csrr[ 	]+a0,pmpaddr2
[ 	]+[0-9a-f]+:[ 	]+3b259073[ 	]+csrw[ 	]+pmpaddr2,a1
[ 	]+[0-9a-f]+:[ 	]+3b302573[ 	]+csrr[ 	]+a0,pmpaddr3
[ 	]+[0-9a-f]+:[ 	]+3b359073[ 	]+csrw[ 	]+pmpaddr3,a1
[ 	]+[0-9a-f]+:[ 	]+3b402573[ 	]+csrr[ 	]+a0,pmpaddr4
[ 	]+[0-9a-f]+:[ 	]+3b459073[ 	]+csrw[ 	]+pmpaddr4,a1
[ 	]+[0-9a-f]+:[ 	]+3b502573[ 	]+csrr[ 	]+a0,pmpaddr5
[ 	]+[0-9a-f]+:[ 	]+3b559073[ 	]+csrw[ 	]+pmpaddr5,a1
[ 	]+[0-9a-f]+:[ 	]+3b602573[ 	]+csrr[ 	]+a0,pmpaddr6
[ 	]+[0-9a-f]+:[ 	]+3b659073[ 	]+csrw[ 	]+pmpaddr6,a1
[ 	]+[0-9a-f]+:[ 	]+3b702573[ 	]+csrr[ 	]+a0,pmpaddr7
[ 	]+[0-9a-f]+:[ 	]+3b759073[ 	]+csrw[ 	]+pmpaddr7,a1
[ 	]+[0-9a-f]+:[ 	]+3b802573[ 	]+csrr[ 	]+a0,pmpaddr8
[ 	]+[0-9a-f]+:[ 	]+3b859073[ 	]+csrw[ 	]+pmpaddr8,a1
[ 	]+[0-9a-f]+:[ 	]+3b902573[ 	]+csrr[ 	]+a0,pmpaddr9
[ 	]+[0-9a-f]+:[ 	]+3b959073[ 	]+csrw[ 	]+pmpaddr9,a1
[ 	]+[0-9a-f]+:[ 	]+3ba02573[ 	]+csrr[ 	]+a0,pmpaddr10
[ 	]+[0-9a-f]+:[ 	]+3ba59073[ 	]+csrw[ 	]+pmpaddr10,a1
[ 	]+[0-9a-f]+:[ 	]+3bb02573[ 	]+csrr[ 	]+a0,pmpaddr11
[ 	]+[0-9a-f]+:[ 	]+3bb59073[ 	]+csrw[ 	]+pmpaddr11,a1
[ 	]+[0-9a-f]+:[ 	]+3bc02573[ 	]+csrr[ 	]+a0,pmpaddr12
[ 	]+[0-9a-f]+:[ 	]+3bc59073[ 	]+csrw[ 	]+pmpaddr12,a1
[ 	]+[0-9a-f]+:[ 	]+3bd02573[ 	]+csrr[ 	]+a0,pmpaddr13
[ 	]+[0-9a-f]+:[ 	]+3bd59073[ 	]+csrw[ 	]+pmpaddr13,a1
[ 	]+[0-9a-f]+:[ 	]+3be02573[ 	]+csrr[ 	]+a0,pmpaddr14
[ 	]+[0-9a-f]+:[ 	]+3be59073[ 	]+csrw[ 	]+pmpaddr14,a1
[ 	]+[0-9a-f]+:[ 	]+3bf02573[ 	]+csrr[ 	]+a0,pmpaddr15
[ 	]+[0-9a-f]+:[ 	]+3bf59073[ 	]+csrw[ 	]+pmpaddr15,a1
[ 	]+[0-9a-f]+:[ 	]+b0002573[ 	]+csrr[ 	]+a0,mcycle
[ 	]+[0-9a-f]+:[ 	]+b0059073[ 	]+csrw[ 	]+mcycle,a1
[ 	]+[0-9a-f]+:[ 	]+b0202573[ 	]+csrr[ 	]+a0,minstret
[ 	]+[0-9a-f]+:[ 	]+b0259073[ 	]+csrw[ 	]+minstret,a1
[ 	]+[0-9a-f]+:[ 	]+b0302573[ 	]+csrr[ 	]+a0,mhpmcounter3
[ 	]+[0-9a-f]+:[ 	]+b0359073[ 	]+csrw[ 	]+mhpmcounter3,a1
[ 	]+[0-9a-f]+:[ 	]+b0402573[ 	]+csrr[ 	]+a0,mhpmcounter4
[ 	]+[0-9a-f]+:[ 	]+b0459073[ 	]+csrw[ 	]+mhpmcounter4,a1
[ 	]+[0-9a-f]+:[ 	]+b0502573[ 	]+csrr[ 	]+a0,mhpmcounter5
[ 	]+[0-9a-f]+:[ 	]+b0559073[ 	]+csrw[ 	]+mhpmcounter5,a1
[ 	]+[0-9a-f]+:[ 	]+b0602573[ 	]+csrr[ 	]+a0,mhpmcounter6
[ 	]+[0-9a-f]+:[ 	]+b0659073[ 	]+csrw[ 	]+mhpmcounter6,a1
[ 	]+[0-9a-f]+:[ 	]+b0702573[ 	]+csrr[ 	]+a0,mhpmcounter7
[ 	]+[0-9a-f]+:[ 	]+b0759073[ 	]+csrw[ 	]+mhpmcounter7,a1
[ 	]+[0-9a-f]+:[ 	]+b0802573[ 	]+csrr[ 	]+a0,mhpmcounter8
[ 	]+[0-9a-f]+:[ 	]+b0859073[ 	]+csrw[ 	]+mhpmcounter8,a1
[ 	]+[0-9a-f]+:[ 	]+b0902573[ 	]+csrr[ 	]+a0,mhpmcounter9
[ 	]+[0-9a-f]+:[ 	]+b0959073[ 	]+csrw[ 	]+mhpmcounter9,a1
[ 	]+[0-9a-f]+:[ 	]+b0a02573[ 	]+csrr[ 	]+a0,mhpmcounter10
[ 	]+[0-9a-f]+:[ 	]+b0a59073[ 	]+csrw[ 	]+mhpmcounter10,a1
[ 	]+[0-9a-f]+:[ 	]+b0b02573[ 	]+csrr[ 	]+a0,mhpmcounter11
[ 	]+[0-9a-f]+:[ 	]+b0b59073[ 	]+csrw[ 	]+mhpmcounter11,a1
[ 	]+[0-9a-f]+:[ 	]+b0c02573[ 	]+csrr[ 	]+a0,mhpmcounter12
[ 	]+[0-9a-f]+:[ 	]+b0c59073[ 	]+csrw[ 	]+mhpmcounter12,a1
[ 	]+[0-9a-f]+:[ 	]+b0d02573[ 	]+csrr[ 	]+a0,mhpmcounter13
[ 	]+[0-9a-f]+:[ 	]+b0d59073[ 	]+csrw[ 	]+mhpmcounter13,a1
[ 	]+[0-9a-f]+:[ 	]+b0e02573[ 	]+csrr[ 	]+a0,mhpmcounter14
[ 	]+[0-9a-f]+:[ 	]+b0e59073[ 	]+csrw[ 	]+mhpmcounter14,a1
[ 	]+[0-9a-f]+:[ 	]+b0f02573[ 	]+csrr[ 	]+a0,mhpmcounter15
[ 	]+[0-9a-f]+:[ 	]+b0f59073[ 	]+csrw[ 	]+mhpmcounter15,a1
[ 	]+[0-9a-f]+:[ 	]+b1002573[ 	]+csrr[ 	]+a0,mhpmcounter16
[ 	]+[0-9a-f]+:[ 	]+b1059073[ 	]+csrw[ 	]+mhpmcounter16,a1
[ 	]+[0-9a-f]+:[ 	]+b1102573[ 	]+csrr[ 	]+a0,mhpmcounter17
[ 	]+[0-9a-f]+:[ 	]+b1159073[ 	]+csrw[ 	]+mhpmcounter17,a1
[ 	]+[0-9a-f]+:[ 	]+b1202573[ 	]+csrr[ 	]+a0,mhpmcounter18
[ 	]+[0-9a-f]+:[ 	]+b1259073[ 	]+csrw[ 	]+mhpmcounter18,a1
[ 	]+[0-9a-f]+:[ 	]+b1302573[ 	]+csrr[ 	]+a0,mhpmcounter19
[ 	]+[0-9a-f]+:[ 	]+b1359073[ 	]+csrw[ 	]+mhpmcounter19,a1
[ 	]+[0-9a-f]+:[ 	]+b1402573[ 	]+csrr[ 	]+a0,mhpmcounter20
[ 	]+[0-9a-f]+:[ 	]+b1459073[ 	]+csrw[ 	]+mhpmcounter20,a1
[ 	]+[0-9a-f]+:[ 	]+b1502573[ 	]+csrr[ 	]+a0,mhpmcounter21
[ 	]+[0-9a-f]+:[ 	]+b1559073[ 	]+csrw[ 	]+mhpmcounter21,a1
[ 	]+[0-9a-f]+:[ 	]+b1602573[ 	]+csrr[ 	]+a0,mhpmcounter22
[ 	]+[0-9a-f]+:[ 	]+b1659073[ 	]+csrw[ 	]+mhpmcounter22,a1
[ 	]+[0-9a-f]+:[ 	]+b1702573[ 	]+csrr[ 	]+a0,mhpmcounter23
[ 	]+[0-9a-f]+:[ 	]+b1759073[ 	]+csrw[ 	]+mhpmcounter23,a1
[ 	]+[0-9a-f]+:[ 	]+b1802573[ 	]+csrr[ 	]+a0,mhpmcounter24
[ 	]+[0-9a-f]+:[ 	]+b1859073[ 	]+csrw[ 	]+mhpmcounter24,a1
[ 	]+[0-9a-f]+:[ 	]+b1902573[ 	]+csrr[ 	]+a0,mhpmcounter25
[ 	]+[0-9a-f]+:[ 	]+b1959073[ 	]+csrw[ 	]+mhpmcounter25,a1
[ 	]+[0-9a-f]+:[ 	]+b1a02573[ 	]+csrr[ 	]+a0,mhpmcounter26
[ 	]+[0-9a-f]+:[ 	]+b1a59073[ 	]+csrw[ 	]+mhpmcounter26,a1
[ 	]+[0-9a-f]+:[ 	]+b1b02573[ 	]+csrr[ 	]+a0,mhpmcounter27
[ 	]+[0-9a-f]+:[ 	]+b1b59073[ 	]+csrw[ 	]+mhpmcounter27,a1
[ 	]+[0-9a-f]+:[ 	]+b1c02573[ 	]+csrr[ 	]+a0,mhpmcounter28
[ 	]+[0-9a-f]+:[ 	]+b1c59073[ 	]+csrw[ 	]+mhpmcounter28,a1
[ 	]+[0-9a-f]+:[ 	]+b1d02573[ 	]+csrr[ 	]+a0,mhpmcounter29
[ 	]+[0-9a-f]+:[ 	]+b1d59073[ 	]+csrw[ 	]+mhpmcounter29,a1
[ 	]+[0-9a-f]+:[ 	]+b1e02573[ 	]+csrr[ 	]+a0,mhpmcounter30
[ 	]+[0-9a-f]+:[ 	]+b1e59073[ 	]+csrw[ 	]+mhpmcounter30,a1
[ 	]+[0-9a-f]+:[ 	]+b1f02573[ 	]+csrr[ 	]+a0,mhpmcounter31
[ 	]+[0-9a-f]+:[ 	]+b1f59073[ 	]+csrw[ 	]+mhpmcounter31,a1
[ 	]+[0-9a-f]+:[ 	]+b8002573[ 	]+csrr[ 	]+a0,mcycleh
[ 	]+[0-9a-f]+:[ 	]+b8059073[ 	]+csrw[ 	]+mcycleh,a1
[ 	]+[0-9a-f]+:[ 	]+b8202573[ 	]+csrr[ 	]+a0,minstreth
[ 	]+[0-9a-f]+:[ 	]+b8259073[ 	]+csrw[ 	]+minstreth,a1
[ 	]+[0-9a-f]+:[ 	]+b8302573[ 	]+csrr[ 	]+a0,mhpmcounter3h
[ 	]+[0-9a-f]+:[ 	]+b8359073[ 	]+csrw[ 	]+mhpmcounter3h,a1
[ 	]+[0-9a-f]+:[ 	]+b8402573[ 	]+csrr[ 	]+a0,mhpmcounter4h
[ 	]+[0-9a-f]+:[ 	]+b8459073[ 	]+csrw[ 	]+mhpmcounter4h,a1
[ 	]+[0-9a-f]+:[ 	]+b8502573[ 	]+csrr[ 	]+a0,mhpmcounter5h
[ 	]+[0-9a-f]+:[ 	]+b8559073[ 	]+csrw[ 	]+mhpmcounter5h,a1
[ 	]+[0-9a-f]+:[ 	]+b8602573[ 	]+csrr[ 	]+a0,mhpmcounter6h
[ 	]+[0-9a-f]+:[ 	]+b8659073[ 	]+csrw[ 	]+mhpmcounter6h,a1
[ 	]+[0-9a-f]+:[ 	]+b8702573[ 	]+csrr[ 	]+a0,mhpmcounter7h
[ 	]+[0-9a-f]+:[ 	]+b8759073[ 	]+csrw[ 	]+mhpmcounter7h,a1
[ 	]+[0-9a-f]+:[ 	]+b8802573[ 	]+csrr[ 	]+a0,mhpmcounter8h
[ 	]+[0-9a-f]+:[ 	]+b8859073[ 	]+csrw[ 	]+mhpmcounter8h,a1
[ 	]+[0-9a-f]+:[ 	]+b8902573[ 	]+csrr[ 	]+a0,mhpmcounter9h
[ 	]+[0-9a-f]+:[ 	]+b8959073[ 	]+csrw[ 	]+mhpmcounter9h,a1
[ 	]+[0-9a-f]+:[ 	]+b8a02573[ 	]+csrr[ 	]+a0,mhpmcounter10h
[ 	]+[0-9a-f]+:[ 	]+b8a59073[ 	]+csrw[ 	]+mhpmcounter10h,a1
[ 	]+[0-9a-f]+:[ 	]+b8b02573[ 	]+csrr[ 	]+a0,mhpmcounter11h
[ 	]+[0-9a-f]+:[ 	]+b8b59073[ 	]+csrw[ 	]+mhpmcounter11h,a1
[ 	]+[0-9a-f]+:[ 	]+b8c02573[ 	]+csrr[ 	]+a0,mhpmcounter12h
[ 	]+[0-9a-f]+:[ 	]+b8c59073[ 	]+csrw[ 	]+mhpmcounter12h,a1
[ 	]+[0-9a-f]+:[ 	]+b8d02573[ 	]+csrr[ 	]+a0,mhpmcounter13h
[ 	]+[0-9a-f]+:[ 	]+b8d59073[ 	]+csrw[ 	]+mhpmcounter13h,a1
[ 	]+[0-9a-f]+:[ 	]+b8e02573[ 	]+csrr[ 	]+a0,mhpmcounter14h
[ 	]+[0-9a-f]+:[ 	]+b8e59073[ 	]+csrw[ 	]+mhpmcounter14h,a1
[ 	]+[0-9a-f]+:[ 	]+b8f02573[ 	]+csrr[ 	]+a0,mhpmcounter15h
[ 	]+[0-9a-f]+:[ 	]+b8f59073[ 	]+csrw[ 	]+mhpmcounter15h,a1
[ 	]+[0-9a-f]+:[ 	]+b9002573[ 	]+csrr[ 	]+a0,mhpmcounter16h
[ 	]+[0-9a-f]+:[ 	]+b9059073[ 	]+csrw[ 	]+mhpmcounter16h,a1
[ 	]+[0-9a-f]+:[ 	]+b9102573[ 	]+csrr[ 	]+a0,mhpmcounter17h
[ 	]+[0-9a-f]+:[ 	]+b9159073[ 	]+csrw[ 	]+mhpmcounter17h,a1
[ 	]+[0-9a-f]+:[ 	]+b9202573[ 	]+csrr[ 	]+a0,mhpmcounter18h
[ 	]+[0-9a-f]+:[ 	]+b9259073[ 	]+csrw[ 	]+mhpmcounter18h,a1
[ 	]+[0-9a-f]+:[ 	]+b9302573[ 	]+csrr[ 	]+a0,mhpmcounter19h
[ 	]+[0-9a-f]+:[ 	]+b9359073[ 	]+csrw[ 	]+mhpmcounter19h,a1
[ 	]+[0-9a-f]+:[ 	]+b9402573[ 	]+csrr[ 	]+a0,mhpmcounter20h
[ 	]+[0-9a-f]+:[ 	]+b9459073[ 	]+csrw[ 	]+mhpmcounter20h,a1
[ 	]+[0-9a-f]+:[ 	]+b9502573[ 	]+csrr[ 	]+a0,mhpmcounter21h
[ 	]+[0-9a-f]+:[ 	]+b9559073[ 	]+csrw[ 	]+mhpmcounter21h,a1
[ 	]+[0-9a-f]+:[ 	]+b9602573[ 	]+csrr[ 	]+a0,mhpmcounter22h
[ 	]+[0-9a-f]+:[ 	]+b9659073[ 	]+csrw[ 	]+mhpmcounter22h,a1
[ 	]+[0-9a-f]+:[ 	]+b9702573[ 	]+csrr[ 	]+a0,mhpmcounter23h
[ 	]+[0-9a-f]+:[ 	]+b9759073[ 	]+csrw[ 	]+mhpmcounter23h,a1
[ 	]+[0-9a-f]+:[ 	]+b9802573[ 	]+csrr[ 	]+a0,mhpmcounter24h
[ 	]+[0-9a-f]+:[ 	]+b9859073[ 	]+csrw[ 	]+mhpmcounter24h,a1
[ 	]+[0-9a-f]+:[ 	]+b9902573[ 	]+csrr[ 	]+a0,mhpmcounter25h
[ 	]+[0-9a-f]+:[ 	]+b9959073[ 	]+csrw[ 	]+mhpmcounter25h,a1
[ 	]+[0-9a-f]+:[ 	]+b9a02573[ 	]+csrr[ 	]+a0,mhpmcounter26h
[ 	]+[0-9a-f]+:[ 	]+b9a59073[ 	]+csrw[ 	]+mhpmcounter26h,a1
[ 	]+[0-9a-f]+:[ 	]+b9b02573[ 	]+csrr[ 	]+a0,mhpmcounter27h
[ 	]+[0-9a-f]+:[ 	]+b9b59073[ 	]+csrw[ 	]+mhpmcounter27h,a1
[ 	]+[0-9a-f]+:[ 	]+b9c02573[ 	]+csrr[ 	]+a0,mhpmcounter28h
[ 	]+[0-9a-f]+:[ 	]+b9c59073[ 	]+csrw[ 	]+mhpmcounter28h,a1
[ 	]+[0-9a-f]+:[ 	]+b9d02573[ 	]+csrr[ 	]+a0,mhpmcounter29h
[ 	]+[0-9a-f]+:[ 	]+b9d59073[ 	]+csrw[ 	]+mhpmcounter29h,a1
[ 	]+[0-9a-f]+:[ 	]+b9e02573[ 	]+csrr[ 	]+a0,mhpmcounter30h
[ 	]+[0-9a-f]+:[ 	]+b9e59073[ 	]+csrw[ 	]+mhpmcounter30h,a1
[ 	]+[0-9a-f]+:[ 	]+b9f02573[ 	]+csrr[ 	]+a0,mhpmcounter31h
[ 	]+[0-9a-f]+:[ 	]+b9f59073[ 	]+csrw[ 	]+mhpmcounter31h,a1
[ 	]+[0-9a-f]+:[ 	]+32002573[ 	]+csrr[ 	]+a0,mcountinhibit
[ 	]+[0-9a-f]+:[ 	]+32059073[ 	]+csrw[ 	]+mcountinhibit,a1
[ 	]+[0-9a-f]+:[ 	]+32302573[ 	]+csrr[ 	]+a0,mhpmevent3
[ 	]+[0-9a-f]+:[ 	]+32359073[ 	]+csrw[ 	]+mhpmevent3,a1
[ 	]+[0-9a-f]+:[ 	]+32402573[ 	]+csrr[ 	]+a0,mhpmevent4
[ 	]+[0-9a-f]+:[ 	]+32459073[ 	]+csrw[ 	]+mhpmevent4,a1
[ 	]+[0-9a-f]+:[ 	]+32502573[ 	]+csrr[ 	]+a0,mhpmevent5
[ 	]+[0-9a-f]+:[ 	]+32559073[ 	]+csrw[ 	]+mhpmevent5,a1
[ 	]+[0-9a-f]+:[ 	]+32602573[ 	]+csrr[ 	]+a0,mhpmevent6
[ 	]+[0-9a-f]+:[ 	]+32659073[ 	]+csrw[ 	]+mhpmevent6,a1
[ 	]+[0-9a-f]+:[ 	]+32702573[ 	]+csrr[ 	]+a0,mhpmevent7
[ 	]+[0-9a-f]+:[ 	]+32759073[ 	]+csrw[ 	]+mhpmevent7,a1
[ 	]+[0-9a-f]+:[ 	]+32802573[ 	]+csrr[ 	]+a0,mhpmevent8
[ 	]+[0-9a-f]+:[ 	]+32859073[ 	]+csrw[ 	]+mhpmevent8,a1
[ 	]+[0-9a-f]+:[ 	]+32902573[ 	]+csrr[ 	]+a0,mhpmevent9
[ 	]+[0-9a-f]+:[ 	]+32959073[ 	]+csrw[ 	]+mhpmevent9,a1
[ 	]+[0-9a-f]+:[ 	]+32a02573[ 	]+csrr[ 	]+a0,mhpmevent10
[ 	]+[0-9a-f]+:[ 	]+32a59073[ 	]+csrw[ 	]+mhpmevent10,a1
[ 	]+[0-9a-f]+:[ 	]+32b02573[ 	]+csrr[ 	]+a0,mhpmevent11
[ 	]+[0-9a-f]+:[ 	]+32b59073[ 	]+csrw[ 	]+mhpmevent11,a1
[ 	]+[0-9a-f]+:[ 	]+32c02573[ 	]+csrr[ 	]+a0,mhpmevent12
[ 	]+[0-9a-f]+:[ 	]+32c59073[ 	]+csrw[ 	]+mhpmevent12,a1
[ 	]+[0-9a-f]+:[ 	]+32d02573[ 	]+csrr[ 	]+a0,mhpmevent13
[ 	]+[0-9a-f]+:[ 	]+32d59073[ 	]+csrw[ 	]+mhpmevent13,a1
[ 	]+[0-9a-f]+:[ 	]+32e02573[ 	]+csrr[ 	]+a0,mhpmevent14
[ 	]+[0-9a-f]+:[ 	]+32e59073[ 	]+csrw[ 	]+mhpmevent14,a1
[ 	]+[0-9a-f]+:[ 	]+32f02573[ 	]+csrr[ 	]+a0,mhpmevent15
[ 	]+[0-9a-f]+:[ 	]+32f59073[ 	]+csrw[ 	]+mhpmevent15,a1
[ 	]+[0-9a-f]+:[ 	]+33002573[ 	]+csrr[ 	]+a0,mhpmevent16
[ 	]+[0-9a-f]+:[ 	]+33059073[ 	]+csrw[ 	]+mhpmevent16,a1
[ 	]+[0-9a-f]+:[ 	]+33102573[ 	]+csrr[ 	]+a0,mhpmevent17
[ 	]+[0-9a-f]+:[ 	]+33159073[ 	]+csrw[ 	]+mhpmevent17,a1
[ 	]+[0-9a-f]+:[ 	]+33202573[ 	]+csrr[ 	]+a0,mhpmevent18
[ 	]+[0-9a-f]+:[ 	]+33259073[ 	]+csrw[ 	]+mhpmevent18,a1
[ 	]+[0-9a-f]+:[ 	]+33302573[ 	]+csrr[ 	]+a0,mhpmevent19
[ 	]+[0-9a-f]+:[ 	]+33359073[ 	]+csrw[ 	]+mhpmevent19,a1
[ 	]+[0-9a-f]+:[ 	]+33402573[ 	]+csrr[ 	]+a0,mhpmevent20
[ 	]+[0-9a-f]+:[ 	]+33459073[ 	]+csrw[ 	]+mhpmevent20,a1
[ 	]+[0-9a-f]+:[ 	]+33502573[ 	]+csrr[ 	]+a0,mhpmevent21
[ 	]+[0-9a-f]+:[ 	]+33559073[ 	]+csrw[ 	]+mhpmevent21,a1
[ 	]+[0-9a-f]+:[ 	]+33602573[ 	]+csrr[ 	]+a0,mhpmevent22
[ 	]+[0-9a-f]+:[ 	]+33659073[ 	]+csrw[ 	]+mhpmevent22,a1
[ 	]+[0-9a-f]+:[ 	]+33702573[ 	]+csrr[ 	]+a0,mhpmevent23
[ 	]+[0-9a-f]+:[ 	]+33759073[ 	]+csrw[ 	]+mhpmevent23,a1
[ 	]+[0-9a-f]+:[ 	]+33802573[ 	]+csrr[ 	]+a0,mhpmevent24
[ 	]+[0-9a-f]+:[ 	]+33859073[ 	]+csrw[ 	]+mhpmevent24,a1
[ 	]+[0-9a-f]+:[ 	]+33902573[ 	]+csrr[ 	]+a0,mhpmevent25
[ 	]+[0-9a-f]+:[ 	]+33959073[ 	]+csrw[ 	]+mhpmevent25,a1
[ 	]+[0-9a-f]+:[ 	]+33a02573[ 	]+csrr[ 	]+a0,mhpmevent26
[ 	]+[0-9a-f]+:[ 	]+33a59073[ 	]+csrw[ 	]+mhpmevent26,a1
[ 	]+[0-9a-f]+:[ 	]+33b02573[ 	]+csrr[ 	]+a0,mhpmevent27
[ 	]+[0-9a-f]+:[ 	]+33b59073[ 	]+csrw[ 	]+mhpmevent27,a1
[ 	]+[0-9a-f]+:[ 	]+33c02573[ 	]+csrr[ 	]+a0,mhpmevent28
[ 	]+[0-9a-f]+:[ 	]+33c59073[ 	]+csrw[ 	]+mhpmevent28,a1
[ 	]+[0-9a-f]+:[ 	]+33d02573[ 	]+csrr[ 	]+a0,mhpmevent29
[ 	]+[0-9a-f]+:[ 	]+33d59073[ 	]+csrw[ 	]+mhpmevent29,a1
[ 	]+[0-9a-f]+:[ 	]+33e02573[ 	]+csrr[ 	]+a0,mhpmevent30
[ 	]+[0-9a-f]+:[ 	]+33e59073[ 	]+csrw[ 	]+mhpmevent30,a1
[ 	]+[0-9a-f]+:[ 	]+33f02573[ 	]+csrr[ 	]+a0,mhpmevent31
[ 	]+[0-9a-f]+:[ 	]+33f59073[ 	]+csrw[ 	]+mhpmevent31,a1
[ 	]+[0-9a-f]+:[ 	]+60002573[ 	]+csrr[ 	]+a0,hstatus
[ 	]+[0-9a-f]+:[ 	]+60059073[ 	]+csrw[ 	]+hstatus,a1
[ 	]+[0-9a-f]+:[ 	]+60202573[ 	]+csrr[ 	]+a0,hedeleg
[ 	]+[0-9a-f]+:[ 	]+60259073[ 	]+csrw[ 	]+hedeleg,a1
[ 	]+[0-9a-f]+:[ 	]+60302573[ 	]+csrr[ 	]+a0,hideleg
[ 	]+[0-9a-f]+:[ 	]+60359073[ 	]+csrw[ 	]+hideleg,a1
[ 	]+[0-9a-f]+:[ 	]+60402573[ 	]+csrr[ 	]+a0,hie
[ 	]+[0-9a-f]+:[ 	]+60459073[ 	]+csrw[ 	]+hie,a1
[ 	]+[0-9a-f]+:[ 	]+60602573[ 	]+csrr[ 	]+a0,hcounteren
[ 	]+[0-9a-f]+:[ 	]+60659073[ 	]+csrw[ 	]+hcounteren,a1
[ 	]+[0-9a-f]+:[ 	]+60702573[ 	]+csrr[ 	]+a0,hgeie
[ 	]+[0-9a-f]+:[ 	]+60759073[ 	]+csrw[ 	]+hgeie,a1
[ 	]+[0-9a-f]+:[ 	]+64302573[ 	]+csrr[ 	]+a0,htval
[ 	]+[0-9a-f]+:[ 	]+64359073[ 	]+csrw[ 	]+htval,a1
[ 	]+[0-9a-f]+:[ 	]+64402573[ 	]+csrr[ 	]+a0,hip
[ 	]+[0-9a-f]+:[ 	]+64459073[ 	]+csrw[ 	]+hip,a1
[ 	]+[0-9a-f]+:[ 	]+64502573[ 	]+csrr[ 	]+a0,hvip
[ 	]+[0-9a-f]+:[ 	]+64559073[ 	]+csrw[ 	]+hvip,a1
[ 	]+[0-9a-f]+:[ 	]+64a02573[ 	]+csrr[ 	]+a0,htinst
[ 	]+[0-9a-f]+:[ 	]+64a59073[ 	]+csrw[ 	]+htinst,a1
[ 	]+[0-9a-f]+:[ 	]+e1202573[ 	]+csrr[ 	]+a0,hgeip
[ 	]+[0-9a-f]+:[ 	]+e1259073[ 	]+csrw[ 	]+hgeip,a1
[ 	]+[0-9a-f]+:[ 	]+60a02573[ 	]+csrr[ 	]+a0,henvcfg
[ 	]+[0-9a-f]+:[ 	]+60a59073[ 	]+csrw[ 	]+henvcfg,a1
[ 	]+[0-9a-f]+:[ 	]+61a02573[ 	]+csrr[ 	]+a0,henvcfgh
[ 	]+[0-9a-f]+:[ 	]+61a59073[ 	]+csrw[ 	]+henvcfgh,a1
[ 	]+[0-9a-f]+:[ 	]+68002573[ 	]+csrr[ 	]+a0,hgatp
[ 	]+[0-9a-f]+:[ 	]+68059073[ 	]+csrw[ 	]+hgatp,a1
[ 	]+[0-9a-f]+:[ 	]+6a802573[ 	]+csrr[ 	]+a0,hcontext
[ 	]+[0-9a-f]+:[ 	]+6a859073[ 	]+csrw[ 	]+hcontext,a1
[ 	]+[0-9a-f]+:[ 	]+60502573[ 	]+csrr[ 	]+a0,htimedelta
[ 	]+[0-9a-f]+:[ 	]+60559073[ 	]+csrw[ 	]+htimedelta,a1
[ 	]+[0-9a-f]+:[ 	]+61502573[ 	]+csrr[ 	]+a0,htimedeltah
[ 	]+[0-9a-f]+:[ 	]+61559073[ 	]+csrw[ 	]+htimedeltah,a1
[ 	]+[0-9a-f]+:[ 	]+20002573[ 	]+csrr[ 	]+a0,vsstatus
[ 	]+[0-9a-f]+:[ 	]+20059073[ 	]+csrw[ 	]+vsstatus,a1
[ 	]+[0-9a-f]+:[ 	]+20402573[ 	]+csrr[ 	]+a0,vsie
[ 	]+[0-9a-f]+:[ 	]+20459073[ 	]+csrw[ 	]+vsie,a1
[ 	]+[0-9a-f]+:[ 	]+20502573[ 	]+csrr[ 	]+a0,vstvec
[ 	]+[0-9a-f]+:[ 	]+20559073[ 	]+csrw[ 	]+vstvec,a1
[ 	]+[0-9a-f]+:[ 	]+24002573[ 	]+csrr[ 	]+a0,vsscratch
[ 	]+[0-9a-f]+:[ 	]+24059073[ 	]+csrw[ 	]+vsscratch,a1
[ 	]+[0-9a-f]+:[ 	]+24102573[ 	]+csrr[ 	]+a0,vsepc
[ 	]+[0-9a-f]+:[ 	]+24159073[ 	]+csrw[ 	]+vsepc,a1
[ 	]+[0-9a-f]+:[ 	]+24202573[ 	]+csrr[ 	]+a0,vscause
[ 	]+[0-9a-f]+:[ 	]+24259073[ 	]+csrw[ 	]+vscause,a1
[ 	]+[0-9a-f]+:[ 	]+24302573[ 	]+csrr[ 	]+a0,vstval
[ 	]+[0-9a-f]+:[ 	]+24359073[ 	]+csrw[ 	]+vstval,a1
[ 	]+[0-9a-f]+:[ 	]+24402573[ 	]+csrr[ 	]+a0,vsip
[ 	]+[0-9a-f]+:[ 	]+24459073[ 	]+csrw[ 	]+vsip,a1
[ 	]+[0-9a-f]+:[ 	]+28002573[ 	]+csrr[ 	]+a0,vsatp
[ 	]+[0-9a-f]+:[ 	]+28059073[ 	]+csrw[ 	]+vsatp,a1
[ 	]+[0-9a-f]+:[ 	]+04302573[ 	]+csrr[ 	]+a0,utval
[ 	]+[0-9a-f]+:[ 	]+04359073[ 	]+csrw[ 	]+utval,a1
[ 	]+[0-9a-f]+:[ 	]+14302573[ 	]+csrr[ 	]+a0,stval
[ 	]+[0-9a-f]+:[ 	]+14359073[ 	]+csrw[ 	]+stval,a1
[ 	]+[0-9a-f]+:[ 	]+18002573[ 	]+csrr[ 	]+a0,satp
[ 	]+[0-9a-f]+:[ 	]+18059073[ 	]+csrw[ 	]+satp,a1
[ 	]+[0-9a-f]+:[ 	]+34302573[ 	]+csrr[ 	]+a0,mtval
[ 	]+[0-9a-f]+:[ 	]+34359073[ 	]+csrw[ 	]+mtval,a1
[ 	]+[0-9a-f]+:[ 	]+32002573[ 	]+csrr[ 	]+a0,mcountinhibit
[ 	]+[0-9a-f]+:[ 	]+32059073[ 	]+csrw[ 	]+mcountinhibit,a1
[ 	]+[0-9a-f]+:[ 	]+38002573[ 	]+csrr[ 	]+a0,0x380
[ 	]+[0-9a-f]+:[ 	]+38059073[ 	]+csrw[ 	]+0x380,a1
[ 	]+[0-9a-f]+:[ 	]+38102573[ 	]+csrr[ 	]+a0,0x381
[ 	]+[0-9a-f]+:[ 	]+38159073[ 	]+csrw[ 	]+0x381,a1
[ 	]+[0-9a-f]+:[ 	]+38202573[ 	]+csrr[ 	]+a0,0x382
[ 	]+[0-9a-f]+:[ 	]+38259073[ 	]+csrw[ 	]+0x382,a1
[ 	]+[0-9a-f]+:[ 	]+38302573[ 	]+csrr[ 	]+a0,0x383
[ 	]+[0-9a-f]+:[ 	]+38359073[ 	]+csrw[ 	]+0x383,a1
[ 	]+[0-9a-f]+:[ 	]+38402573[ 	]+csrr[ 	]+a0,0x384
[ 	]+[0-9a-f]+:[ 	]+38459073[ 	]+csrw[ 	]+0x384,a1
[ 	]+[0-9a-f]+:[ 	]+38502573[ 	]+csrr[ 	]+a0,0x385
[ 	]+[0-9a-f]+:[ 	]+38559073[ 	]+csrw[ 	]+0x385,a1
[ 	]+[0-9a-f]+:[ 	]+32102573[ 	]+csrr[ 	]+a0,0x321
[ 	]+[0-9a-f]+:[ 	]+32159073[ 	]+csrw[ 	]+0x321,a1
[ 	]+[0-9a-f]+:[ 	]+32202573[ 	]+csrr[ 	]+a0,0x322
[ 	]+[0-9a-f]+:[ 	]+32259073[ 	]+csrw[ 	]+0x322,a1
[ 	]+[0-9a-f]+:[ 	]+00102573[ 	]+csrr[ 	]+a0,fflags
[ 	]+[0-9a-f]+:[ 	]+00159073[ 	]+csrw[ 	]+fflags,a1
[ 	]+[0-9a-f]+:[ 	]+00202573[ 	]+csrr[ 	]+a0,frm
[ 	]+[0-9a-f]+:[ 	]+00259073[ 	]+csrw[ 	]+frm,a1
[ 	]+[0-9a-f]+:[ 	]+00302573[ 	]+csrr[ 	]+a0,fcsr
[ 	]+[0-9a-f]+:[ 	]+00359073[ 	]+csrw[ 	]+fcsr,a1
[ 	]+[0-9a-f]+:[ 	]+7b002573[ 	]+csrr[ 	]+a0,dcsr
[ 	]+[0-9a-f]+:[ 	]+7b059073[ 	]+csrw[ 	]+dcsr,a1
[ 	]+[0-9a-f]+:[ 	]+7b102573[ 	]+csrr[ 	]+a0,dpc
[ 	]+[0-9a-f]+:[ 	]+7b159073[ 	]+csrw[ 	]+dpc,a1
[ 	]+[0-9a-f]+:[ 	]+7b202573[ 	]+csrr[ 	]+a0,dscratch0
[ 	]+[0-9a-f]+:[ 	]+7b259073[ 	]+csrw[ 	]+dscratch0,a1
[ 	]+[0-9a-f]+:[ 	]+7b302573[ 	]+csrr[ 	]+a0,dscratch1
[ 	]+[0-9a-f]+:[ 	]+7b359073[ 	]+csrw[ 	]+dscratch1,a1
[ 	]+[0-9a-f]+:[ 	]+7b202573[ 	]+csrr[ 	]+a0,dscratch0
[ 	]+[0-9a-f]+:[ 	]+7b259073[ 	]+csrw[ 	]+dscratch0,a1
[ 	]+[0-9a-f]+:[ 	]+7a002573[ 	]+csrr[ 	]+a0,tselect
[ 	]+[0-9a-f]+:[ 	]+7a059073[ 	]+csrw[ 	]+tselect,a1
[ 	]+[0-9a-f]+:[ 	]+7a102573[ 	]+csrr[ 	]+a0,tdata1
[ 	]+[0-9a-f]+:[ 	]+7a159073[ 	]+csrw[ 	]+tdata1,a1
[ 	]+[0-9a-f]+:[ 	]+7a202573[ 	]+csrr[ 	]+a0,tdata2
[ 	]+[0-9a-f]+:[ 	]+7a259073[ 	]+csrw[ 	]+tdata2,a1
[ 	]+[0-9a-f]+:[ 	]+7a302573[ 	]+csrr[ 	]+a0,tdata3
[ 	]+[0-9a-f]+:[ 	]+7a359073[ 	]+csrw[ 	]+tdata3,a1
[ 	]+[0-9a-f]+:[ 	]+7a402573[ 	]+csrr[ 	]+a0,tinfo
[ 	]+[0-9a-f]+:[ 	]+7a459073[ 	]+csrw[ 	]+tinfo,a1
[ 	]+[0-9a-f]+:[ 	]+7a502573[ 	]+csrr[ 	]+a0,tcontrol
[ 	]+[0-9a-f]+:[ 	]+7a559073[ 	]+csrw[ 	]+tcontrol,a1
[ 	]+[0-9a-f]+:[ 	]+7a802573[ 	]+csrr[ 	]+a0,mcontext
[ 	]+[0-9a-f]+:[ 	]+7a859073[ 	]+csrw[ 	]+mcontext,a1
[ 	]+[0-9a-f]+:[ 	]+7aa02573[ 	]+csrr[ 	]+a0,scontext
[ 	]+[0-9a-f]+:[ 	]+7aa59073[ 	]+csrw[ 	]+scontext,a1
[ 	]+[0-9a-f]+:[ 	]+7a102573[ 	]+csrr[ 	]+a0,tdata1
[ 	]+[0-9a-f]+:[ 	]+7a159073[ 	]+csrw[ 	]+tdata1,a1
[ 	]+[0-9a-f]+:[ 	]+7a102573[ 	]+csrr[ 	]+a0,tdata1
[ 	]+[0-9a-f]+:[ 	]+7a159073[ 	]+csrw[ 	]+tdata1,a1
[ 	]+[0-9a-f]+:[ 	]+7a102573[ 	]+csrr[ 	]+a0,tdata1
[ 	]+[0-9a-f]+:[ 	]+7a159073[ 	]+csrw[ 	]+tdata1,a1
[ 	]+[0-9a-f]+:[ 	]+7a102573[ 	]+csrr[ 	]+a0,tdata1
[ 	]+[0-9a-f]+:[ 	]+7a159073[ 	]+csrw[ 	]+tdata1,a1
[ 	]+[0-9a-f]+:[ 	]+7a302573[ 	]+csrr[ 	]+a0,tdata3
[ 	]+[0-9a-f]+:[ 	]+7a359073[ 	]+csrw[ 	]+tdata3,a1
[ 	]+[0-9a-f]+:[ 	]+7a302573[ 	]+csrr[ 	]+a0,tdata3
[ 	]+[0-9a-f]+:[ 	]+7a359073[ 	]+csrw[ 	]+tdata3,a1
[ 	]+[0-9a-f]+:[ 	]+01502573[ 	]+csrr[ 	]+a0,seed
[ 	]+[0-9a-f]+:[ 	]+01559073[ 	]+csrw[ 	]+seed,a1
[ 	]+[0-9a-f]+:[ 	]+00802573[ 	]+csrr[ 	]+a0,vstart
[ 	]+[0-9a-f]+:[ 	]+00859073[ 	]+csrw[ 	]+vstart,a1
[ 	]+[0-9a-f]+:[ 	]+00902573[ 	]+csrr[ 	]+a0,vxsat
[ 	]+[0-9a-f]+:[ 	]+00959073[ 	]+csrw[ 	]+vxsat,a1
[ 	]+[0-9a-f]+:[ 	]+00a02573[ 	]+csrr[ 	]+a0,vxrm
[ 	]+[0-9a-f]+:[ 	]+00a59073[ 	]+csrw[ 	]+vxrm,a1
[ 	]+[0-9a-f]+:[ 	]+00f02573[ 	]+csrr[ 	]+a0,vcsr
[ 	]+[0-9a-f]+:[ 	]+00f59073[ 	]+csrw[ 	]+vcsr,a1
[ 	]+[0-9a-f]+:[ 	]+c2002573[ 	]+csrr[ 	]+a0,vl
[ 	]+[0-9a-f]+:[ 	]+c2059073[ 	]+csrw[ 	]+vl,a1
[ 	]+[0-9a-f]+:[ 	]+c2102573[ 	]+csrr[ 	]+a0,vtype
[ 	]+[0-9a-f]+:[ 	]+c2159073[ 	]+csrw[ 	]+vtype,a1
[ 	]+[0-9a-f]+:[ 	]+c2202573[ 	]+csrr[ 	]+a0,vlenb
[ 	]+[0-9a-f]+:[ 	]+c2259073[ 	]+csrw[ 	]+vlenb,a1
