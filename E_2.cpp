#include <iostream>
#include <helib/helib.h>

helib::Ctxt E_2(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt tmp2 = ctxt;
    helib::Ctxt res = ctxt;
    helib::Ptxt<helib::BGV> ptxt(ctxt.getContext());
    long n = ea.size();

    for (int i = 0; i < n; ++i){
        ptxt[i] = 1;
    }
    ptxt[n-1] = 0;

    ea.rotate(tmp1, -1);
    tmp1 *= ptxt;
    res *= tmp1;
    tmp1 = ctxt;

    for (int i = 1; i < (n-1); ++i)
    {
        ea.rotate(tmp1, -i-1);
        ptxt[n-i-1] = 0;

        tmp1 *= ptxt;
        tmp2 *= tmp1;
        res += tmp2;

        tmp2 = ctxt;
        tmp1 = ctxt;
    }
    helib::totalSums(ea, res);

    return res;
}


helib::Ctxt E_2_V2(const helib::EncryptedArray& ea, helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt tmp2 = ctxt;
    helib::Ctxt res = ctxt;
    long n = ea.size();

    ea.rotate(tmp1, -1);
    res *= tmp1;
    tmp1 = ctxt;

    for (int i = 1; i < (n-1); ++i){
        ea.rotate(tmp1, -i-1);

        tmp2 *= tmp1;
        res += tmp2;

        tmp2 = ctxt;
        tmp1 = ctxt;
    }
    helib::totalSums(ea, res);

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
                               .m(32763)
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
    
    helib::Ptxt<helib::BGV> ptxt(context);
    for (int i = 0; i < ptxt.size(); ++i) {
        ptxt[i] = i;
    }
    
    helib::Ctxt ctxt(public_key);
    public_key.Encrypt(ctxt, ptxt);

    helib::Ctxt tmp = ctxt;
    helib::Ctxt ctxt_res(public_key);
    helib::Ptxt<helib::BGV> result(context);


    std::cout << "E_2 V1 " << std::endl;
    for(int i=0; i<10; i++){
        tmp = ctxt;
        HELIB_NTIMER_START(timer_v1);
        ctxt_res = E_2(ea, tmp);
        HELIB_NTIMER_STOP(timer_v1);
    }
    helib::printNamedTimer(std::cout, "timer_v1");
    secret_key.Decrypt(result, ctxt_res);
    std::cout << "Decrypted Result: " << result << std::endl;

    std::cout << "E_2 V2 " << std::endl;
    for(int i=0; i<10; i++){
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