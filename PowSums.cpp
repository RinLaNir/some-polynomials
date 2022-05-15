#include <iostream>
#include <helib/helib.h>
#include <NTL/BasicThreadPool.h>

// The function evaluates the power sum symmetric polynomial.
//
// const arg ea: Data-movement operations on arrays of slots (helib::EncryptedArray)
// arg ctxt: Сryptotext of BGV scheme (helib::Ctxt)
// const arg power: power of the variables (long)

void PowerSumSymm(const helib::EncryptedArray& ea, helib::Ctxt & ctxt, const long power)
{
  ctxt.power(power);
  helib::totalSums(ea, ctxt); 
}

// The function evaluates the power sum symmetric polynomial
// using standard arithmetic without homomorphic encryption.
// 
// const arg ea: Data-movement operations on arrays of slots (helib::EncryptedArray)
// const arg ctxt: Сryptotext of BGV scheme (helib::Ctxt)
// const arg power: power of the variables

long long BrutPowerSumSymm(const std::vector<long>& arr, const long power)
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
    
    // ptxt = [1,2,3,4,5,...,nslots]
    helib::Ptxt<helib::BGV> ptxt(context);
    for (int i = 0; i < ptxt.size(); ++i) {
        ptxt[i] = i+1;
    }
    
    helib::Ctxt ctxt(public_key);
    public_key.Encrypt(ctxt, ptxt);

    helib::Ptxt<helib::BGV> plaintext_result(context);
    helib::Ctxt tmp = ctxt;

    // arr = [1,2,3,4,5,...,nslots]
    std::vector<long> arr;
    for (long i = 0L; i < ptxt.size(); ++i) {
        arr.emplace_back(i+1);
    }

    for(int power=1; power<=11; power++){
        std::cout << "PowerSums for i = " << power << std::endl;
        for(int j=0; j<10; j++){
            tmp = ctxt;
            HELIB_NTIMER_START(timer_ctxt);
            PowerSumSymm(ea, tmp, power);
            HELIB_NTIMER_STOP(timer_ctxt);

            HELIB_NTIMER_START(timer_brut);
            BrutPowerSumSymm(arr, power);
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