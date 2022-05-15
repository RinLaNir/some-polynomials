#include <iostream>
#include <helib/helib.h>

// Calculation of the elementary symmetric polynomial for k=2.
// const arg ea: Data-movement operations on arrays of slots (helib::EncryptedArray)
// const arg ctxt: Сryptotext of BGV scheme (helib::Ctxt)

/* -------------------------- Version 1 ---------------------------------*/

// Input: C - cryptotext
// res = 0
// for i <-- 1 to n do
//     res <-- res + C * (C <<< i)
// res <-- TotalSums(res)
// Return: res

helib::Ctxt E_2_V1(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt tmp2 = ctxt;
    helib::Ctxt res = ctxt;
    
    long n = ea.size();                    // number of slots
    
    ea.shift(tmp1, -1);                    // ctxt <<< 1
    
    res *= tmp1;                           // = ctxt * (ctxt <<< 1)
    tmp1 = ctxt;                           // to avoid noise accumulation

    for (int i = 2; i < n; ++i)
    {
        HELIB_NTIMER_START(timer_E2_V1);
        
        ea.shift(tmp1, -i);                // ctxt <<< i

        tmp2 *= tmp1;                      // ctxt * (ctxt <<< i)
        res += tmp2;                       // res + ctxt * (ctxt <<< i)

        tmp2 = ctxt;
        tmp1 = ctxt;
        
        HELIB_NTIMER_STOP(timer_E2_V1);
    }
    helib::totalSums(ea, res);             // TotalSums(res)
    
    helib::printNamedTimer(std::cout, "timer_E2_V1");

    return res;
}


/* -------------------------- Version 2 ---------------------------------*/

// Input: C - cryptotext
// sum = 0
// orig = 0
// for i <-- 1 to n do
//     sum <-- sum + (C >>> i)
// orig <-- C * sum
// orig <-- TotalSums(orig)
// Return: orig

helib::Ctxt E_2_V2(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt orig = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();

    ea.shift(sum, 1);                    // sum + C >>> 1

    for (int i = 2; i < n; ++i)
    {
        HELIB_NTIMER_START(timer_E2_V3);

        ea.shift(tmp1, i);               // C >>> i
        sum += tmp1;                     // sum + C >>> i
        tmp1 = ctxt;

        HELIB_NTIMER_STOP(timer_E2_V3);
    }
    orig *= sum;                         // orig * sum
    helib::totalSums(ea, orig);          // TotalSums(orig)

    helib::printNamedTimer(std::cout, "timer_E2_V3");

    return orig;
}




int main(int argc, char* argv[])
{
  std::cout << "Initialising context object..." << std::endl;
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(32663)
                               .p(2)
                               .r(31)
                               .bits(350)
                               .c(2)
                               .build();
    context.printout();
    std::cout << std::endl;
    
    std::cout << "Creating secret key..." << std::endl;
    helib::SecKey secret_key(context);
    secret_key.GenSecKey();

    std::cout << "Generating key-switching matrices..." << std::endl;
    helib::addSome1DMatrices(secret_key);
    
    const helib::PubKey& public_key = secret_key;
    const helib::EncryptedArray& ea = context.getEA();
    
    long nslots = ea.size();
    std::cout << "Number of slots: " << nslots << std::endl;
    
    // ptxt = [1,2,3,4,5,...,nslots]
    helib::Ptxt<helib::BGV> ptxt(context);
    for (int i = 0; i < ptxt.size(); ++i) {
        ptxt[i] = i+1;
    }
    
    helib::Ctxt ctxt(public_key);
    public_key.Encrypt(ctxt, ptxt);

    helib::Ctxt tmp = ctxt;
    helib::Ctxt ctxt_res(public_key);
    helib::Ptxt<helib::BGV> result(context);

    std::cout << "E_2 V1" << std::endl;
    for(int i=0; i<5; i++){
        tmp = ctxt;
        HELIB_NTIMER_START(timer_v1);
        ctxt_res = E_2_V1(ea, tmp);
        HELIB_NTIMER_STOP(timer_v1);
    }
    helib::printNamedTimer(std::cout, "timer_v1");
    secret_key.Decrypt(result, ctxt_res);
    std::cout << "Decrypted Result: " << result << std::endl;

    std::cout << "E_2 V2" << std::endl;
    for(int i=0; i<5; i++){
        tmp = ctxt;
        HELIB_NTIMER_START(timer_v2);
        ctxt_res = E_2_V2(ea, tmp);
        HELIB_NTIMER_STOP(timer_v2);
    }
    helib::printNamedTimer(std::cout, "timer_v2");
    secret_key.Decrypt(result, ctxt_res);
    std::cout << "Decrypted Result: " << result << std::endl;

    return 0;
}