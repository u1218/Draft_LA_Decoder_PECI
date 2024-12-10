die_id_map =  { 0  : 'IO Die0',
                9  : 'Compute Die0',
                10 : 'Compute Die1',
                11 : 'Compute Die2',
                4  : 'IO Die1' } 


internal_dev_map = {(30, 30, 2) : ['SPD0',        'SPD',          0, 0xff],
                    (30, 30, 3) : ['SPD1',        'SPD',          0, 0xff],
                    (30, 30, 6) : ['SPD2',        'SPD',         11, 0xff],
                    (30, 30, 7) : ['SPD3',        'SPD',         11, 0xff],
                    ( 8,  3, 0) : ['OOBMSM',      'OOBMSM',       0, 0x00],
                    ( 8,  3, 1) : ['OOBMSM PMON', 'OOBMSM_PMON',  0, 0x00],
                    (30,  0, 2) : ['UBOX DECS',   'UBOX_DECS',    0, 0x00] }
