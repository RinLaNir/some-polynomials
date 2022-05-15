#include <iostream>
#include <helib/helib.h>
#include <NTL/BasicThreadPool.h>

// Calculation of the elementary symmetric polynomial for k=3.
// const arg ea: Data-movement operations on arrays of slots (helib::EncryptedArray)
// const arg ctxt: Сryptotext of BGV scheme (helib::Ctxt)


/* -------------------------- Version 1 ---------------------------------*/

// Calculation of the elementary symmetric polynomial for k=2 without TotalSums.
// This is a modification of the function E_2 version 2 from file E_2.cpp.
// Used in the E_3_V1 function. 

// Input: C - cryptotext
// sum = 0
// for i <-- 1 to n do
//     sum <-- sum + (C >>> i)
// res = C * sum
// Return: res

helib::Ctxt E_2_V1(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt orig = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();

    ea.shift(sum, 1);

    for (int i = 1; i < (n-1); ++i)
    {
        ea.shift(tmp1, i+1);
        sum += tmp1;
        tmp1 = ctxt;
    }
    orig *= sum;

    return orig;
}

// Input: C -- cryptotext
// res_e2 = E_2(C) -- result of modified E_2
// sum = 0
// for i <-- 1 to n-1 do
//     sum <-- sum + (C <<< i)
// res = res_e2 * sum
// res <-- TotalSums(res)
// Return: res

helib::Ctxt E_3_V1(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt res_e2 = E_2_V1(ea,ctxt);  // E_2(C)

    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();                 // number of slots

    ea.shift(sum, -1);                  // sum + (C <<< 1)

    for (int i = 2; i < n-1; ++i){
        ea.shift(tmp1, -i);             // C <<< i

        sum += tmp1;                    // sum + (C <<< i)
        tmp1 = ctxt;
    }
    res_e2 *= sum;                      // res_e2 * sum

    helib::totalSums(ea, res_e2);       // TotalSums(res)
    return res_e2;
}

/* -------------------------- Version 2 ---------------------------------*/

// Calculation of the elementary symmetric polynomial for k=2 without TotalSums
// and multiplication at the end.
// This is a modification of the function E_2 version 2 from file E_2.cpp.
// Used in the E_3_V2 function. 

// Input: C - cryptotext
// sum = 0
// for i <-- 1 to n do
//     sum <-- sum + (C >>> i)
// Return: sum

helib::Ctxt E_2_V2(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();

    ea.shift(sum, 1);

    for (int i = 1; i < (n-1); ++i)
    {
        ea.shift(tmp1, i+1);
        sum += tmp1;
        tmp1 = ctxt;
    }
    return sum;
}

// Input: C -- cryptotext
// sum_e2 = E_2(C) -- result of modified E_2
// sum = 0
// for i <-- 1 to n-1 do
//     sum <-- sum + (C <<< i)
// res = C * (sum_e2 * sum)
// res <-- TotalSums(res)
// Return: res

helib::Ctxt E_3_V2(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt sum_e2 = E_2_V2(ea,ctxt);

    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt res = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();

    ea.shift(sum, -1);                 // sum + (C <<< 1)

    for (int i = 2; i < n-1; ++i){
        ea.shift(tmp1, -i);            // C <<< i

        sum += tmp1;                   // sum + (C <<< i)
        tmp1 = ctxt;
    }
    sum_e2 *= sum;                     // sum_e2 * sum
    res *= sum_e2;                    // C * (sum_e2 * sum)

    helib::totalSums(ea, res);        // TotalSums(res)
    return res;
}



helib::Ptxt<helib::BGV> ResPowerSum(std::vector<helib::Ctxt>& ctxt_arr, helib::SecKey& secret_key)
{
  helib::Ptxt<helib::BGV> plaintext_result(ctxt_arr[0].getContext());
  helib::Ptxt<helib::BGV> plaintext_temp(ctxt_arr[0].getContext());
  for (int i=0; i < ctxt_arr.size(); i++){
    secret_key.Decrypt(plaintext_temp, ctxt_arr[i]);
    plaintext_result += plaintext_temp;
  }

  plaintext_result.totalSums();
  return plaintext_result;
}

int main(int argc, char* argv[])
{
  std::cout << "Initialising context object..." << std::endl;
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(12663) //32663  2657 22661 22659
                               .p(2)
                               .r(31)
                               .bits(500)
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


    std::cout << "E_3_V1 " << std::endl;
    for(int i=0; i<1; i++){
        tmp = ctxt;
        HELIB_NTIMER_START(timer_v1);
        ctxt_res = E_3_V1(ea, tmp);
        HELIB_NTIMER_STOP(timer_v1);
    }
    helib::printNamedTimer(std::cout, "timer_v1");
    secret_key.Decrypt(result, ctxt_res);
    std::cout << "Decrypted Result: " << result << std::endl;

    std::cout << "E_3_V2 " << std::endl;
    for(int i=0; i<1; i++){
        tmp = ctxt;
        HELIB_NTIMER_START(timer_v2);
        ctxt_res = E_3_V2(ea, tmp);
        HELIB_NTIMER_STOP(timer_v2);
    }
    helib::printNamedTimer(std::cout, "timer_v2");
    secret_key.Decrypt(result, ctxt_res);
    std::cout << "Decrypted Result: " << result << std::endl;

    return 0;
}