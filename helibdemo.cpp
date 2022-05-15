#include <iostream>
#include <helib/helib.h>

void PowerSumSymm(const helib::EncryptedArray& ea, helib::Ctxt & ctxt, const long power)
{
  ctxt.power(power);
  helib::totalSums(ea, ctxt); 
}

long long BrutPowerSumSymm(const std::vector<long>& arr, const long power)
{
  long long sum = 0;
  for (long i = 0L; i < arr.size(); ++i){
    sum += std::pow(arr[i], power);
  }
  return sum;
}


helib::Ctxt E_2(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt orig = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();

    ea.shift(sum, 1);

    for (int i = 2; i < n; ++i)
    {
        ea.shift(tmp1, i);
        sum += tmp1;
        tmp1 = ctxt;
    }
    orig *= sum;
    helib::totalSums(ea, orig);

    return orig;
}

helib::Ctxt util_E_2(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
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


helib::Ctxt E_3(const helib::EncryptedArray& ea, const helib::Ctxt & ctxt)
{
    helib::Ctxt sum_e2 = util_E_2(ea,ctxt);

    helib::Ctxt tmp1 = ctxt;
    helib::Ctxt res = ctxt;
    helib::Ctxt sum = ctxt;
    long n = ea.size();

    ea.shift(sum, -1);

    for (int i = 2; i < n-1; ++i){
        ea.shift(tmp1, -i);

        sum += tmp1;
        tmp1 = ctxt;
    }
    sum_e2 *= sum;
    res *= sum_e2;

    helib::totalSums(ea, res);
    return res;
}

int main(int argc, char* argv[])
{
  // Plaintext prime modulus
  unsigned long p = 2;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 32763;
  // Hensel lifting (default = 1)
  unsigned long r = 32;
  // Number of bits of the modulus chain
  unsigned long bits = 350;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;

  std::cout << "Initialising context object..." << std::endl;

  // Initialize context
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();

  // Print the context
  context.printout();
  std::cout << std::endl;

  // Print the security level
  std::cout << "Security: " << context.securityLevel() << std::endl;

  // Secret key management
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context
  helib::SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  std::cout << "Generating key-switching matrices..." << std::endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const helib::PubKey& public_key = secret_key;

  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = context.getEA();

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

  // Create a vector of long with nslots elements
  helib::Ptxt<helib::BGV> ptxt(context);
  // Set it with numbers 1..nslots
  //ptxt = [1] [2] [3] ... [nslots-1] [nslots]
  for (int i = 0; i < ptxt.size(); ++i) {
    ptxt[i] = i+1;
  }

  std::cout << "Plaintext: " << ptxt << std::endl;

    
  // Create a ciphertext object
  helib::Ctxt ctxt(public_key);
  // Encrypt the plaintext using the public_key
  public_key.Encrypt(ctxt, ptxt);


  int power = 4;

  std::cout << std::endl << "Eval power sum symmetric polynomial with power = " << power << std::endl;

  HELIB_NTIMER_START(timer_PowerSum);
  PowerSumSymm(ea, ctxt, power);
  HELIB_NTIMER_STOP(timer_PowerSum);

  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, ctxt);

  std::cout << "Decrypted Result: " << plaintext_result << std::endl;


  helib::printNamedTimer(std::cout, "timer_PowerSum");

  ctxt.clear();
  public_key.Encrypt(ctxt, ptxt);

  std::cout << std::endl << "Eval elementary symmetric polynomial with k = 2" << std::endl;
  
  HELIB_NTIMER_START(timer_E_2);
  helib::Ctxt res = E_2(ea, ctxt);
  HELIB_NTIMER_STOP(timer_E_2);

  secret_key.Decrypt(plaintext_result, res);
  std::cout << "Decrypted Result: " << plaintext_result << std::endl;

  helib::printNamedTimer(std::cout, "timer_E_2");

  ctxt.clear();
  public_key.Encrypt(ctxt, ptxt);

  std::cout << std::endl << "Eval elementary symmetric polynomial with k = 3" << std::endl;
  
  HELIB_NTIMER_START(timer_E_3);
  res = E_3(ea, ctxt);
  HELIB_NTIMER_STOP(timer_E_3);

  secret_key.Decrypt(plaintext_result, res);
  std::cout << "Decrypted Result: " << plaintext_result << std::endl;

  helib::printNamedTimer(std::cout, "timer_E_3");

  return 0;
}