    Scope (\_SB)
    {
        Device (EPC)
        {
            Name (_HID, EisaId ("INT0E0C"))
            Name (_STR, Unicode ("Enclave Page Cache 1.5"))
            Name (_MLS, Package (0x01)
            {
                Package (0x02)
                {
                    "en",
                    Unicode ("Enclave Page Cache 1.5")
                }
            })
            Method (_CRS, 0, NotSerialized) // _CRS: Current Recourse Settings
            {
                Store (ResourceTemplate ()
                {
                    QWordMemory (ResourceConsumer, PosDecode, MinFixed, MaxFixed,
                        Cacheable, ReadWrite,
                        0x0000000000000000, // Granularity
                        0x0000000000000000, // Range Minimum
                        0x0000000000000000, // Range Maximum
                        0x0000000000000000, // Translation Offset
                        0x0000000000000001, // Length
                        ,, _Y03,
                        AddressRangeMemory, TypeStatic)
                }, Local1)

                If(LEqual(Zero, \_SB.EPC._CRS._Y03)) {
                    Subtract(\_SB.EPC._CRS._Y03._MIN, 14, Local0)
                } Else {
                    Store(\_SB.EPC._CRS._Y03, Local0)
                }

                CreateDwordField (Local1, Add(Local0, 14), MINL) // MINL: Minimum Base Address (low 32bits)
                CreateDwordField (Local1, Add(local0, 18), MINH) // MINH: Minimum Base Address (high 32bits)
                CreateDwordField (Local1, Add(local0, 22), MAXL) // MAXL: Maximum Base Address (low 32bits)
                CreateDwordField (Local1, Add(local0, 26), MAXH) // MAXH: Maximum Base Address (high 32bits)
                CreateDwordField (Local1, Add(local0, 38), LENL) // LENL: Length (low 32bits)
                CreateDwordField (Local1, Add(local0, 42), LENH) // LENH: Length (high 32bits)

                Store (\_SB.EMNL, MINL)
                Store (\_SB.EMNH, MINH)
                Store (\_SB.ELNL, LENL)
                Store (\_SB.ELNH, LENH)

                Add (MINL, LENL, MAXL)
                Add (MINH, LENH, MAXH)

                If(LLess(MAXL, MINL)) {
                    Add(MAXH, One, MAXH)
                }

                If(LOr(MINH, LENL)) {
                    If(LEqual(MAXL, 0)) {
                        Subtract(MAXH, One, MAXH)
                    }
                    Subtract(MAXL, One, MAXL)
                }

                Return (Local1)
            }

            Method (_STA, 0, NotSerialized) // _STA: Status
            {
                IF ((\_SB.ELNL != Zero) && (\_SB.ELNH != Zero))
                {
                    Return (0x0F)
                }

                Return (Zero)
            }
        }
    }
