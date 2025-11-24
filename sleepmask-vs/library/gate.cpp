#include <windows.h>

// Include bof-vs header files
#include "beacon_gate.h"
#include "sleepmask.h"

// Include sleepmask-vs specific header files
#include "..\debug.h"
#include "..\sleepmask-vs.h"

/**
* A wrapper around BeaconGate to handle masking/unmasking Beacon
*
* @param info A pointer to a BEACON_INFO structure
* @param gateFunction A pointer to a FUNCTION_CALL structure
*/
void BeaconGateWrapper(PBEACON_INFO info, PFUNCTION_CALL gateFunction) {
    if (gateFunction->bMask == TRUE) {
        MaskBeacon(info);
    }

    BeaconGate(gateFunction);

    if (gateFunction->bMask == TRUE) {
        UnMaskBeacon(info);
    }

    return;
}

/**
* Execute BeaconGate.
*
* @param gateFunction A pointer to a FUNCTION_CALL structure
*/
void BeaconGate(PFUNCTION_CALL gateFunction) {
    ULONG_PTR retValue = 0;
    
    /** 
    * Call appropriate function pointer based on number of args.
    *
    * Note: This is not a switch statement because it adds linker
    * errors. 
    */
#if ENABLE_LOGGING
    PrintBeaconGateInfo(gateFunction);
#endif
    if (gateFunction->numOfArgs == 0) {
        retValue = beaconGate(00)();
    }
    else if (gateFunction->numOfArgs == 1) {
        retValue = beaconGate(01)(arg(0));
    }
    else if (gateFunction->numOfArgs == 2) {
        retValue = beaconGate(02)(arg(0), arg(1));
    }
    else if (gateFunction->numOfArgs == 3) {
        retValue = beaconGate(03) (arg(0), arg(1), arg(2));
    }
    else if (gateFunction->numOfArgs == 4) {
        retValue = beaconGate(04) (arg(0), arg(1), arg(2), arg(3));
    }
    else if (gateFunction->numOfArgs == 5) {
        retValue = beaconGate(05) (arg(0), arg(1), arg(2), arg(3), arg(4));
    }
    else if (gateFunction->numOfArgs == 6) {
        retValue = beaconGate(06) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5));
    }
    else if (gateFunction->numOfArgs == 7) {
        retValue = beaconGate(07) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6));
    }
    else if (gateFunction->numOfArgs == 8) {
        retValue = beaconGate(08) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7));
    }
    else if (gateFunction->numOfArgs == 9) {
        retValue = beaconGate(09) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8));
    }
    else if (gateFunction->numOfArgs == 10) {
        retValue = beaconGate(10) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8), arg(9));
    }

    gateFunction->retValue = retValue;
    DLOGF("BEACONGATE: Return value: 0x%p\n", retValue);

    return;
}
