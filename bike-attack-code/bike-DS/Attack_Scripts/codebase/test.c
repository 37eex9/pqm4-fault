
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <math.h>

#include "gf2x.h"
#include "kem.h"
#include "measurements.h"
#include "utilities.h"
#include "cpu_features.h"
#include <omp.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
// #include "types.h"

//#include "patterns.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))



// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>> Public Variables <<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

#define sk_size 5223
#define pk_size 1541
#define ct_size 1573
#define ss_size 32
#define file_name_length 120

char key_file_name[file_name_length] = "key.txt";
char data_file_name[file_name_length] = "data.txt";
int percent_to_print = 10;
char folder_to_safe[file_name_length] = "Enc_data";





// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>> Parallel Config <<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

int num_threads = 1;
// 0 -> max
void set_num_of_threads(int threads)
{
  if(num_threads == threads) return;
#ifdef _OPENMP
  if (!threads)
    num_threads = omp_get_max_threads();
  else
    num_threads = min(omp_get_max_threads(), threads);

  // Set the number of threads to the maximum
  omp_set_num_threads(num_threads);
  printf("utilizing %d Threads ! \n", num_threads);
#else
  num_threads = 1;
  printf("Single Thread ! \n");
#endif
}


void set_print_percentile(int count_per_thread)
{
  if (count_per_thread < 100)
    percent_to_print = count_per_thread;
  else if (count_per_thread < 1000)
    percent_to_print = 5;
  else if (count_per_thread < 5000)
    percent_to_print = 10;
  else if (count_per_thread < 20000)
    percent_to_print = 20;
  else
    percent_to_print = 100;
}




// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>> IO and Save to File Stuff <<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

int does_folder_exist(const char folderPath[file_name_length]){
  printf("Check folder : \" %s \" \n", folderPath);
  struct stat st;
  return stat(folderPath, &st) == 0;
}

int folder_contains_keyfile(const char folderPath[file_name_length]){
  struct dirent *entry;
  int contains = 0; 
  DIR *dir = opendir(folderPath);

  while ((entry = readdir(dir)) != NULL) {
      if (strcmp(entry->d_name, "key.txt") == 0) {
          printf("folder contains a key.txt file \n");
          contains = 1;
          break;
      }
  }

  closedir(dir);

  return contains; 
}

int is_file_in_folder(const char *folderPath, const char *fileName) {
    // Concatenate folderPath and fileName to get the full path of the file
    char fullPath[256]; // Adjust the size as needed
    snprintf(fullPath, sizeof(fullPath), "%s/%s", folderPath, fileName);

    // Try to open the file
    FILE *file = fopen(fullPath, "r");
    if (file != NULL) {
        // File exists in the folder
        fclose(file);
        return 1;
    } else {
        // File does not exist in the folder
        return 0;
    }
}


void get_file_path(char* file_path, char* folder_name,  char* keyfile_name){
  snprintf(file_path, file_name_length, "%s/%s", folder_name, keyfile_name);
}


void save_key(char* fileName, unsigned char* sk){

  FILE *file = fopen(fileName, "a");
  if (file != NULL){
    for (int i = 0; i < sk_size; i++)
      fprintf(file, "%02x", sk[i]);
    fprintf(file, "\n");

    fflush(file);
    fclose(file);
  }
  else
    printf("Error opening the file.\n");
}

// complicated method to read the keys, we can just memcopy, but anyways it works...
int read_faulty_keys(unsigned char ***sk_list, unsigned char ***pk_list, int *amount, char *filename)
{
  FILE *file = fopen(filename, "r"); // Assuming text file with hex dumps

  if (file == NULL)
  {
    perror("Error opening file");
    return 1;
  }

  // 2* 4(byte) *71 wlist entries, 3* R_Bytes (h0, h1, h) + M_BYTES = ep
  int length_key_in_bytes = 2 * 4 * 71 + 3 * R_BYTES + M_BYTES;

  // ------ READ all data ----
  if (file == NULL)
  {
    perror("Error opening file");
    return 1;
  }

  // Get the file size
  fseek(file, 0, SEEK_END);
  long fileSize = ftell(file);
  fseek(file, 0, SEEK_SET);

  // Allocate memory to store the file content
  char *hexString = malloc(fileSize + 1);

  if (hexString == NULL)
  {
    perror("Memory allocation error");
    fclose(file);
    return 1;
  }

  // Read the file content into the hexString buffer
  fread(hexString, 1, fileSize, file);

  // Null-terminate the string
  hexString[fileSize] = '\0';

  fclose(file);

  // Calculate the length of the string
  size_t hexStringLength = strlen(hexString);
  size_t numBytes = 0;

  // Create an array to store the bytes
  unsigned char byteArray[hexStringLength];

  // Convert hex string to byte array but remove newlines
  int pos = 0;
  while(pos < hexStringLength){
    if(hexString[pos] != '\n'){
      sscanf(&hexString[pos], "%2hhx", &byteArray[numBytes]);
      pos+=2;
      numBytes++;
    }
    else{
      pos++;
    }
  }
  int keys_read = numBytes/length_key_in_bytes;

  unsigned char **sk = malloc(keys_read * sizeof(char *));
  unsigned char **pk = malloc(keys_read * sizeof(char *));
  // take each key
  for (int i = 0; i < keys_read; i++)
  {

    sk[i] = malloc(sk_size * sizeof(char));
    pk[i] = malloc(pk_size * sizeof(char));
    uint8_t *sk_pos = &byteArray[0] + (length_key_in_bytes)*i;
    uint8_t *pk_pos = &byteArray[0] + (length_key_in_bytes)*i + 2 * 4 * 71 + 2 * R_BYTES;

    // without newline
    memcpy(sk[i], sk_pos, length_key_in_bytes);
    memcpy(pk[i], pk_pos, R_BYTES);
  }
  *sk_list = sk;
  *pk_list = pk;
  *amount = keys_read;
  
  free(hexString);

  printf("Successfully read byte array\n");

  return 0;
}



void readNumberFromTerminal(int *x) {
    printf("Enter a number: ");
    scanf("%d", x);
}

void exit_program(){
  printf("Terminating program \n");
  exit(0);
}


// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>> Dist spec stuff <<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

#define DIST_SPEC_LEN (R_BITS/2 +1) // [0 : R_BITS/2]
#define DIST_SPEC_MAX_DIST R_BITS/2 
const int amount_when_saved = 100000;
// setting to enable a change for the errors for testing
int change_e = 0;
int num_of_fixed_positions = 0;

void set_change_e(int length_e){
  change_e = 1;
  num_of_fixed_positions = length_e;
}

void save_dist_spec(char* fileName, int** dist_spec, int** dist_spec_sum, int succ){
  
  char file_path[file_name_length]; 
  get_file_path(file_path, fileName, data_file_name);
  FILE *file = fopen(file_path, "a");
  if (file != NULL){

      fprintf(file, "%d,%d\n", succ, amount_when_saved);

      for (int i = 0; i < DIST_SPEC_LEN; i++)
        fprintf(file, "%d,", dist_spec[0][i]);
      fprintf(file, "\n");
      for (int i = 0; i < DIST_SPEC_LEN; i++)
        fprintf(file, "%d,", dist_spec_sum[0][i]);
      fprintf(file, "\n");


      for (int i = 0; i < DIST_SPEC_LEN; i++)
        fprintf(file, "%d,", dist_spec[1][i]);
      fprintf(file, "\n");
      for (int i = 0; i < DIST_SPEC_LEN; i++)
        fprintf(file, "%d,", dist_spec_sum[1][i]);
      fprintf(file, "\n");;

      
      fflush(file);
      fclose(file); 
    
  }
  else printf("Error opening the file.\n");
}

void save_enc_data(char *fileName, struct Meta_Info_enc* info, int rounds){

  FILE *file = fopen(fileName, "a");
  if (file != NULL)
  {

    for (int r = 0; r < rounds; r++)
    {
      fprintf(file, "%d\n", info[r].succ);

    for (int i = 0; i < R_BYTES; i++)
      fprintf(file, "%02x", info[r].e0[i]);
    fprintf(file, "\n");

    for (int i = 0; i < R_BYTES; i++)
      fprintf(file, "%02x", info[r].e1[i]);
    fprintf(file, "\n");
  
    /*
    for (int i = 0; i < R_BYTES; i++)
      fprintf(file, "%02x", info[r].c0[i]);
    fprintf(file, "\n");*/
    } 
    
    fflush(file);
    fclose(file); 
  
  }
  else printf("Error opening the file.\n");
}

// get a out_arr of len > anzahl fehler über e0 und e1
void get_w_list(OUT int* out_arr, OUT int* arr_len, IN unsigned char* e){

  int pos =0;
  
  for(size_t i = 0; i < R_BYTES; i++){
    if(e[i] > 0){
      for (size_t b = 0; b < 8; b++){
        if(e[i] & (1 << b)){
          out_arr[pos] = i*8+b; 
          pos++;
        }
      }
    }
  }
  *arr_len = pos;
}

void update_dist_spec(int* dist_spec, int* dist_spec_sum, unsigned char* e, int succ){
  
  // fix length for bike
  int w_list_e[200];
  int w_list_len;
  get_w_list(w_list_e, &w_list_len, e);
  if(w_list_len > 120){
    printf("\n \n probably an Error  cause wlist len = %d \n\n\n", w_list_len);
  }



  int cur_dist_seen[DIST_SPEC_LEN] = {0};
  for (size_t i = 0; i < w_list_len; i++){
    for (size_t j = i+1; j < w_list_len; j++){
     
      int a = w_list_e[i];
      int b = w_list_e[j];
      int l = succ ? 0 : 1;
      
      int dist;
      if(b-a > DIST_SPEC_MAX_DIST) dist = R_BITS - (b-a);
      else dist = (b-a);

      if( !cur_dist_seen[dist]){
        dist_spec[dist] += l;
        dist_spec_sum[dist] += 1;
        cur_dist_seen[dist] = 1;
      }
      if(dist < 0 ){
        exit(0);
      }
    }
  }
  return;
}







// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>> BIKE Key encaps and decaps apis <<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

int set_bit_in_e(uint8_t* a, int bit) {
    // Shift 1 to the left by the specified bit position
    uint8_t mask = 1 << bit%8;

    // Use bitwise AND to check if the bit is set
    if((a[bit/8] & mask) > 0){
      return 0;
    }
    else{
      a[bit/8] |= mask;

      return 1;
    }
}

// custom example function to change the structre of e_0
int change_ei(OUT unsigned char* e_0, OUT unsigned char* e_1){

  int counted_in_e0 = 0;
  for(int i = 0; i < R_BYTES; i++){
    counted_in_e0 += __builtin_popcount(e_0[i]);
    e_0[i] = 0;
  }

  int pos_to_fix = rand() % R_BITS;

  int wanted_fixed_pos = num_of_fixed_positions;
  int num_fixed_pos = min(wanted_fixed_pos,counted_in_e0);
  for (int i = 0; i < num_fixed_pos; i++)
  {
    set_bit_in_e(e_0, (pos_to_fix +i) % R_BITS);
    counted_in_e0--;
  }
  
  while (counted_in_e0 > 0){
    int pos = rand() % R_BITS;
    if(set_bit_in_e(e_0 , pos)) counted_in_e0--;
  }
  
  e_1[0] = e_1[0];

  
  return 0;
}

// simple enc dec cylces times and returns the number of successes but in parallel
// used by par_enc_dec_dist_spec.
// >inp do_print : 1 for debug print
// >inp cycles : for number of enc & dec
// >OUT dist_spec / dist_spec_sum which stores the distspec for the keys
// >OUT optional pointer dec_info:  ( can be left NULL)
// >inp sk / pk : the corresponding key 
int enc_dec_dist_spec(
    IN int do_print,
    IN int cycles,
    OUT struct Meta_Info *dec_info,
    OUT int** dist_spec,
    OUT int** dist_spec_sum,
    IN unsigned char *pk,
    IN unsigned char *sk)
{

  unsigned char *ct = malloc(ct_size * sizeof(char));
  unsigned char *ss_enc = malloc(ss_size * sizeof(char));
  unsigned char *ss_dec = malloc(ss_size * sizeof(char));
  unsigned char **e_out_enc = malloc(2 * sizeof(unsigned char*));
  unsigned char **e_out_dec = malloc(2 * sizeof(unsigned char*));
  for (int i = 0; i < 2; i++){
    e_out_enc[i] = malloc(R_BYTES * sizeof(unsigned char));
    e_out_dec[i] = malloc(R_BYTES * sizeof(unsigned char));
  }

  int out_size = M_BYTES + 1;
  unsigned char *out = malloc(out_size * sizeof(char));

  int count_succ = 0;
  int percent = 0;

  // start time tracking
  struct timeval start_time, end_time;
  gettimeofday(&start_time, NULL);

  // run all tests
  for (int i = 0; i < cycles; i++)
  {
    char succ = 0;
    int ret;
    struct Meta_Info_enc meta_enc;

    if(change_e){
      ret = crypto_kem_enc_changed_e(ct, ss_enc, e_out_enc, pk, (Change_Error_Vectors_Fun)&change_ei);
    }
    else{
      // use normal error vectors
      ret = crypto_kem_enc_changed_e(ct, ss_enc, e_out_enc, pk, NULL);
    }
    
    
    ret = crypto_kem_dec_changed_e(ss_dec, e_out_dec, ct, sk);



    // check if e_out_enc and e_out_dec are the same -> success
    succ = 1;
    for (int i = 0; i < R_BYTES; i++)
    {
      if(e_out_enc[0][i] != e_out_dec[0][i]) succ = 0;
      if(e_out_enc[1][i] != e_out_dec[1][i]) succ = 0;
    }

    if(succ){
      count_succ++;
    }
    
    update_dist_spec(dist_spec[0], dist_spec_sum[0], e_out_enc[0], succ);
    update_dist_spec(dist_spec[1], dist_spec_sum[1], e_out_enc[1], succ);

    // print status
    if (do_print)
    {
      if (((i + 1) % (cycles / percent_to_print)) == 0)
      {
        percent += (int)((float)1 / percent_to_print * 100);

        gettimeofday(&end_time, NULL);
        double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + (double)(end_time.tv_usec - start_time.tv_usec) / 1000000.0;
        printf("- at %d%%  with time %.2f \n", percent, elapsed_time);
      }
    }
  }

  for (int i = 0; i < 2; i++){
    free(e_out_enc[i]);
    free(e_out_dec[i]);
  }
  free(e_out_enc);
  free(e_out_dec);

  free(ct);
  free(ss_enc);
  free(ss_dec);
  free(out);
  return count_succ;
}


// simple enc dec clycle times and returns the number of successes but in parallel
// automatically saves the distance spectrum after 'amount_when_saved' cycles into "data.txt" into the folder !Appends!
int par_enc_dec_dist_spec(
    IN int cycles,
    IN unsigned char *pk,
    IN unsigned char *sk,
    char* folderName)
{
  printf("   >> enc and dec for %d rounds \n", cycles);
  int count_succ = 0;

  struct timeval start_time, end_time, start_time_int, end_time_int ;
  gettimeofday(&start_time, NULL);

  // set the number of threads to cycles if cylces < threads
  set_num_of_threads(min(cycles, num_threads));

  set_print_percentile(cycles / num_threads);
  int percent = 0;


  printf("Save every %d samples \n", amount_when_saved);
  printf("Cycles to do %d \n", cycles / num_threads);

// run the enc_dec() in even : cycle/num_threads chunks and collect all succ
  #pragma omp parallel for reduction(+ : count_succ)
  for (int i = 0; i < num_threads; i++)
  {
    int cycles_tmp;
    unsigned char *sk_tmp = malloc(sk_size * sizeof(char));
    unsigned char *pk_tmp = malloc(pk_size * sizeof(char));
    cycles_tmp = cycles / num_threads;
    int cycles_to_do = cycles_tmp;
    if(omp_get_thread_num() == 0){
      cycles_to_do += cycles % num_threads;
    }

    int cycles_done = 0;
    memcpy(pk_tmp, pk, pk_size);
    memcpy(sk_tmp, sk, sk_size); 

    // dist_spec
    int** dist_spec = malloc(2 * sizeof(int*));
    int** dist_spec_sum = malloc(2 * sizeof(int*));
    for (size_t y = 0; y < 2; y++){
      dist_spec[y] = malloc(DIST_SPEC_LEN * sizeof(int));
      dist_spec_sum[y] = malloc(DIST_SPEC_LEN * sizeof(int));

      // Set all elements to zero
      memset(dist_spec[y], 0, DIST_SPEC_LEN * sizeof(int));
      memset(dist_spec_sum[y], 0, DIST_SPEC_LEN * sizeof(int));
    }
    
    
    int amount_to_save = amount_when_saved;
    int cur_cycles;

    // change 1 -> for print outputs
    int first_run = 1;
    while (1)
    {
      cur_cycles = min(cycles_to_do, amount_to_save);
      cycles_to_do -= cur_cycles;
      
      // print status
      if (omp_get_thread_num() == 0)
      {
        printf("cur_cycles : %d / %d \n", cycles_done, cycles_to_do);
        if(first_run == 1){
          gettimeofday(&start_time_int, NULL);
          first_run--;
        }
        else if(first_run == 0){
          gettimeofday(&end_time_int, NULL);  
          double elapsed_time_int = (end_time_int.tv_sec - start_time_int.tv_sec) + (double)(end_time_int.tv_usec - start_time_int.tv_usec) / 1000000.0;
          double total_seconds = elapsed_time_int * (cycles_tmp / amount_to_save);
          int hours = (int)(total_seconds / 3600); // Number of hours
          int minutes = (int)((total_seconds - (hours * 3600)) / 60); // Number of minutes
          int seconds = (int)(total_seconds - (hours * 3600) - (minutes * 60)); // Number of seconds

          printf("Estimated time when finished: %d hours, %d minutes, %d seconds\n", hours, minutes, seconds);
          first_run--;
        }
        cycles_done += cur_cycles;
      }

       int succ_cur = enc_dec_dist_spec(0, cur_cycles, NULL, dist_spec, dist_spec_sum, pk_tmp, sk_tmp);
       count_succ += succ_cur;
        


      #pragma omp critical
      {
        save_dist_spec(folderName, dist_spec, dist_spec_sum, succ_cur);
      }
      
      if(cycles_to_do == 0)break;
      

    
      // reset your dist spec data to zero
      for (size_t y = 0; y < 2; y++){
      // Set all elements to zero
        memset(dist_spec[y], 0, DIST_SPEC_LEN * sizeof(int));
        memset(dist_spec_sum[y], 0, DIST_SPEC_LEN * sizeof(int));
      }
    }

    free(pk_tmp);
    free(sk_tmp);
    for (size_t y = 0; y < 2; y++) {
        free(dist_spec[y]);
        free(dist_spec_sum[y]);
    }
    free(dist_spec);
    free(dist_spec_sum);

    }
  
gettimeofday(&end_time, NULL);  
double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + (double)(end_time.tv_usec - start_time.tv_usec) / 1000000.0;
printf("time %.2f seconds\n", elapsed_time);


  printf("\n");
  printf("------------------------------------\n");
  printf("---ALL------------------------------\n");
  printf("---- Successes  / Failures ---------\n");
  printf("----       %d   / %d       ---------\n", count_succ, cycles - count_succ);
  printf("----       %f   / %f       ---------\n", (double)count_succ / cycles * 100, ((double)cycles - count_succ) / cycles * 100);
  printf("------------------------------------\n");
  printf("\n");

  return count_succ;
}




// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>> Functions to tests variations <<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

/*
// foldername to save the key and custom_key 0 -> normal; 1 (else)-> pattern
int generate_new_key_and_save(const char *folder_name, int custom_key){
  
  unsigned char *sk = malloc(sk_size * sizeof(char));
  unsigned char *pk = malloc(pk_size * sizeof(char));

  char pattern_inp[file_name_length] = "pattern4";

  if(custom_key == 0){
    printf("gen normal key \n");
    int t = crypto_kem_keypair(pk, sk);
  }
  else{
    printf("gen pattern key \n");
    int err_0 = 1;
    int err_1 = 0;
    unsigned char dummy0[1];
    unsigned char dummy1[1];
    // generate with custom pattern -> see faulty pattern.c for patterns
    Insert_Custom_Error_Function fault_pattern;
    int ret = get_pattern(pattern_inp, err_0, err_1, NULL, &fault_pattern);
    if(ret == 0) return 0; // no sutiable error values for fault pattern

    int t = gen_faulty_key(err_0, err_1, fault_pattern, dummy0, dummy1, pk, sk);

  }

  // save key
  
  if(!does_folder_exist(folder_name)){
    printf("||||||||||| Folder does not exist |||||||||||||||||||\n");
    exit_program();
  }
  else if(does_folder_exist(folder_name)){
    if(!folder_contains_keyfile(folder_name)){
      printf("||||||||||| Save data to folder \" %s \" |||||||||||||||||||\n", folder_name);
    }
    else{
      printf("||||||||||| There is a key.txt already saved in Folder \" %s \" |||||||||||||||||||\n", folder_name);
      exit_program();
    }
  }
  

  char file_path[file_name_length];
  get_file_path(file_path, (char*)folder_name, key_file_name);
  printf("save to  : %s \n", file_path);

  save_key(file_path, sk);



  free(sk);
  free(pk);
}
*/


// given a folder name with a corresponding key.txt file (first key in file if more than one)
// collect the distance spectrum for the inputed amount of keys
int collect_dist_for_key(const char *folder_name){

  if(!does_folder_exist(folder_name)){
    printf("||||||||||| Folder does not exist |||||||||||||||||||\n");
    exit_program();
  }
  if(!is_file_in_folder(folder_name, key_file_name)){
    printf("||||||||||| No key.txt file in folder |||||||||||||||||||\n");
    exit_program();
  }

  unsigned char **sk_list;
  unsigned char **pk_list;
  int amount;

  char file_path[file_name_length]; 
  get_file_path(file_path, (char*)folder_name, key_file_name);
  read_faulty_keys(&sk_list, &pk_list, &amount, file_path);

  if(amount != 1){
    printf("||||||||||| more than one key in file (%d many) |||||||||||||||||||\n", amount);
    //exit_program();
  }

  printf("||||||||||| How many do you want to collect |||||||||||||||||||\n");
  int runs = 0;
  readNumberFromTerminal(&runs);

  printf("||||||||||| How many threads (0 for max) |||||||||||||||||||\n");
  int used_threads = 0;
  readNumberFromTerminal(&used_threads);
  set_num_of_threads(used_threads);


  // update folder path
  memcpy(folder_to_safe, folder_name, file_name_length);
  int count = par_enc_dec_dist_spec(runs, pk_list[0], sk_list[0], (char*)folder_name);


}





// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>> main <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

int main(int argc, char *argv[])
{

  // Initialize the CPU features flags
  cpu_features_init();
#if defined(FIXED_SEED)
  srand(0);
#else
  srand(time(NULL));
#endif

  
    if (argc < 2) {
        printf("Usage: %s <directory> [--change_e <number>]\n", argv[0]);
        return 1;
    }

    char *folder_name = argv[1];
    printf("Folder: %s\n", folder_name);

    int change_e_flag = 0;
    int change_e_value = 0;

    // Optionales Argument prüfen
    if (argc >= 3) {
        if (strcmp(argv[2], "--change_e") == 0) {
            if (argc >= 4) {
                change_e_flag = 1;
                change_e_value = atoi(argv[3]);
            } else {
                printf("Error: --change_e benötigt eine Zahl!\n");
                return 1;
            }
        } else {
            printf("Unbekanntes Argument: %s\n", argv[2]);
            return 1;
        }
    }

    if (change_e_flag) {
        printf("--change_e aktiviert mit Wert: %d\n", change_e_value);
        set_change_e(change_e_value);
    }



  collect_dist_for_key(folder_name);

}


