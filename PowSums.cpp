#include <iostream>
#include <helib/helib.h>

void PowerSum(const helib::EncryptedArray& ea, helib::Ctxt & ctxt, long power)
{
  ctxt.power(power);
  helib::totalSums(ea, ctxt);
}

long long BrutPowerSum(const std::vector<long>& arr, long power)
{
  long long sum = 0;
  for (long i = 0L; i < arr.size(); ++i){
    sum += std::pow(arr[i], power);
  }

  return sum;
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

    helib::Ptxt<helib::BGV> plaintext_result(context);
    helib::Ctxt tmp = ctxt;

    std::vector<long> arr;
    for (long i = 0L; i < ptxt.size(); ++i) {
        arr.emplace_back(i);
    }

    for(int power=1; power<=11; power++){
        std::cout << "PowerSums for i = " << power << std::endl;
        for(int j=0; j<10; j++){
            tmp = ctxt;
            HELIB_NTIMER_START(timer_ctxt);
            PowerSum(ea, tmp, power);
            HELIB_NTIMER_STOP(timer_ctxt);

            HELIB_NTIMER_START(timer_brut);
            BrutPowerSum(arr, power);
            HELIB_NTIMER_STOP(timer_brut);
        }

        secret_key.Decrypt(plaintext_result, tmp);

        helib::printNamedTimer(std::cout, "timer_ctxt");
        helib::printNamedTimer(std::cout, "timer_brut");
        std::cout << "Decrypt data: " << plaintext_result << std::endl << std::endl;
        helib::resetAllTimers();
    }

    return 0;
}