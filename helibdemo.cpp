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

std::vector<helib::Ctxt> E_2(const helib::EncryptedArray& ea, helib::Ctxt & ctxt)
{
  helib::Ctxt tmp1 = ctxt;
  helib::Ctxt tmp2 = ctxt;
  helib::Ctxt res = ctxt;
  helib::Ptxt<helib::BGV> ptxt(ctxt.getContext());
  long n = ea.size();

  for (int i = 0; i < n; ++i)
  {
    ptxt[i] = 1;
  }
  ptxt[n-1] = 0;

  ea.rotate(tmp1, -1);
  tmp1 *= ptxt;
  res *= tmp1;
  tmp1 = ctxt;
  std::vector<helib::Ctxt> ctxt_arr;

  for (int i = 1; i < (n-1); ++i)
  {
    ea.rotate(tmp1, -i-1);
    ptxt[n-i-1] = 0;

    if (!res.isCorrect()){
      ctxt_arr.emplace_back(res);
      res.clear();
    }

    tmp1 *= ptxt;
    tmp2 *= tmp1;
    res += tmp2;

    tmp2 = ctxt;
    tmp1 = ctxt;
    
  }

  ctxt_arr.emplace_back(res);

  return ctxt_arr;
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
  // Plaintext prime modulus
  unsigned long p = 2;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 32763;
  // Hensel lifting (default = 1)
  unsigned long r = 31;
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
  // Set it with numbers 0..nslots - 1
  //ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
  for (int i = 0; i < ptxt.size(); ++i) {
    ptxt[i] = i;
  }

    
  // Create a ciphertext object
  helib::Ctxt ctxt(public_key);
  // Encrypt the plaintext using the public_key
  public_key.Encrypt(ctxt, ptxt);


  int power = 2;

  HELIB_NTIMER_START(timer_ptxt);
  PowerSum(ea, ctxt, power);
  //ctxt.totalSums();
  HELIB_NTIMER_STOP(timer_ptxt);

  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, ctxt);

  std::cout << "Decrypted Result: " << plaintext_result << std::endl;

  std::vector<long> arr;
  for (long i = 0L; i < ptxt.size(); ++i) {
    arr.emplace_back(i);
  }
  long long sum;

  HELIB_NTIMER_START(timer_brut);
  sum = BrutPowerSum(arr, power);
  HELIB_NTIMER_STOP(timer_brut);
  
  std::cout << sum << std::endl;

  helib::printNamedTimer(std::cout << std::endl, "timer_ptxt");
  helib::printNamedTimer(std::cout, "timer_brut");

  ctxt.clear();
  public_key.Encrypt(ctxt, ptxt);
  helib::Ctxt res(public_key);
  std::vector<helib::Ctxt> ctxt_arr = E_2(ea, ctxt);

  helib::Ptxt result = ResPowerSum(ctxt_arr, secret_key);
  std::cout << "Decrypted Result: " << result << std::endl;

  return 0;
}