import numpy as np
import tensorflow as tf
import csv
import time
import os
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.models import load_model


num_bits = 12323
num_dist = (num_bits // 2) +1
start_cut = 0
end_cut = 0



def top_20_percent_lowering_peaks(y_true, y_pred):
    # Flatten the predictions and true labels
    y_true = tf.reshape(y_true, [-1])
    y_pred = tf.reshape(y_pred, [-1])
    
    # Get the number of points in the top 20%
    top_20_percent_count = tf.cast(tf.math.round(0.2 * tf.cast(tf.size(y_pred), tf.float32)), tf.int32)
    
    # Get the indices that would sort y_pred in descending order
    top_pred_indices = tf.argsort(y_pred, direction='DESCENDING')[:top_20_percent_count]
    
    # Gather the true labels for the top 20% predicted points
    top_true_labels = tf.gather(y_true, top_pred_indices)
    
    # Count how many of the true labels in the top 20% are actually lowering peaks (where y_true == 1)
    lowering_peak_hits = tf.reduce_sum(tf.cast(top_true_labels == 1, tf.float32))
    
    # Calculate the proportion of lowering peaks detected in the top 20%
    total_lowering_peaks = tf.reduce_sum(tf.cast(y_true == 1, tf.float32))
    proportion_lowering_peaks_in_top_20 = lowering_peak_hits / (total_lowering_peaks + tf.keras.backend.epsilon())
    
    return proportion_lowering_peaks_in_top_20



def get_fully_connected_model():
    
    
    model = Sequential([
        Conv1D(32, kernel_size=33, padding='same', activation='relu', input_shape=(num_dist - (start_cut + end_cut), 1)),
        Conv1D(64, kernel_size=3, padding='same', activation='relu'),
        Conv1D(128, kernel_size=2, padding='same', activation='relu'),

        Conv1D(1, kernel_size=1, padding='same', activation='sigmoid')  # Outputs a prediction for each input point

    ])
    
  

    optimizer = 'adam'
    model.compile(optimizer=optimizer, loss=tf.keras.losses.BinaryCrossentropy(), metrics=[top_20_percent_lowering_peaks])
    

    return model




def read_trace_file(how_many_to_read, filename):
    

    keys = []
    DS = []
    still_todo = how_many_to_read
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        for i, row in enumerate(reader):
            

            if i % 2 == 0:
                # This is an even line (0-based index, so even number)
                # Convert strings to integers
                values = [int(value.strip()) for value in row]
                keys.append(values)
            else:
                # This is an odd line (0-based index, so odd number)
                # Convert strings to floats
                values = [float(value.strip()) for value in row]
                DS.append(values)
                still_todo -= 1
            
            if still_todo == 0:
                break
        print(f"read {how_many_to_read- still_todo} traces")
    keys_array = np.array(keys)
    DS_array = np.array(DS)

    return keys_array, DS_array



def det_dist_in_spec(s, i):
    a = 0
    b = 0
    if s < i:
        a = s
        b = i
    else:
        a = i
        b = s
    max_dist = num_bits // 2
    if (b-a) > max_dist:
        return num_bits - (b-a)
    else:
        return (b-a)
    



def find_middle_position(wlist):
    """
    Find the middle position of the only consecutive block in wlist 
    that has length >= 30.
    Returns the index (in wlist) of the middle element of that block.
    """

    max_start, max_len = 0, 0
    current_start, current_len = 0, 1

    for i in range(1, len(wlist)):
        if wlist[i] == wlist[i-1] + 1: 
            current_len += 1
        else:
            if current_len >= max_len:
                max_len = current_len
                max_start = current_start
            current_start = i
            current_len = 1

    # check last
    if current_len >= max_len:
        max_len = current_len
        max_start = current_start

    if max_len < 30:
        raise ValueError("No valid block in key")

    middle_index = max_start + max_len // 2
    return wlist[middle_index]



# get the respective label for the block
def get_train_labels_from_key(wlist):
    interesting_points = np.zeros(num_dist)
    blockcenter = find_middle_position(wlist) 
    for pos in wlist:
        if(pos > 100 ):
            interesting_points[det_dist_in_spec(blockcenter, pos)] = 1
    
    for i in range(0, 100):
        interesting_points[i] = 0
    

    return interesting_points



# which_labeling = 0 -> key range , 1 -> single key pos
def get_traces(trace_to_do, filename):

    keys, DS = read_trace_file(trace_to_do, filename)

    labels = []
    for k in keys:
        labels.append(get_train_labels_from_key(k))
    labels = np.array(labels)

    print("labels : ", keys[0])
    return DS, labels


def standardize(data):
    mean = np.mean(data)
    std = np.std(data)
    return (data - mean) / std

def min_max_normalize(data):
    min_val = np.min(data)
    max_val = np.max(data)
    return (data - min_val) / (max_val - min_val)

def normalize_data(data):
    for i in range(len(data)):
        data[i] = min_max_normalize(data[i])

    return data


def print_Top_K_Evaluation(eval_pred, eval_truth, top_pred):
    # Top-K Evaluation
    num_top_predictions = top_pred
    top_k_indices = np.argsort(eval_pred)[-num_top_predictions:]  # Top K predictions
    lowering_indices = np.where(eval_truth == 1)[0]  # Actual Valley points

    # Find how many Valley points were correctly predicted
    correctly_predicted_mask = np.isin(lowering_indices, top_k_indices)
    correctly_predicted_count = np.sum(correctly_predicted_mask)

    # Print the results
    print(f" For  {num_top_predictions}  Number of seleceted distances: {correctly_predicted_count} out of {len(lowering_indices)}, are included : {len(lowering_indices)- correctly_predicted_count}")

    # returns the number of points the model missed
    return len(lowering_indices)- correctly_predicted_count


def get_old_model(model_name):
    
    # Define custom_objects to include metric
    custom_objects = {
        'top_20_percent_lowering_peaks': top_20_percent_lowering_peaks
    }

    # Load the model without compiling
    loaded_model = load_model(model_name, custom_objects=None, compile=False)

    # Compile the model manually metrics
    loaded_model.compile(optimizer='adam', loss=tf.keras.losses.BinaryCrossentropy(), metrics=[top_20_percent_lowering_peaks])

    # Now you can use the model

    return loaded_model


os.putenv("CUDA_VISIBLE_DEVICES", "0") #TODO: Choose GPU
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"


# TODO change for your file
filename = './../test_key/test_trace.csv'
use_old_model = 1
num_samples = 1 
num_test_samples = 1 

trace_to_do = num_samples - num_test_samples


if(use_old_model):
    #model_filename =  'pre_trained_models/2k.h5'
    model_filename =  'pre_trained_models/10k.h5'

    model = get_old_model(model_filename)
else:
    # train new model

    DS, peaks = get_traces(trace_to_do, filename)
    DS = normalize_data(DS)

    X_train = DS[:, (0+start_cut):(num_dist-end_cut)].reshape(trace_to_do, num_dist - (start_cut + end_cut), 1)
    y_train = peaks[:, (0+start_cut):(num_dist-end_cut)].reshape(trace_to_do, num_dist - (start_cut + end_cut), 1)

    # Get model
    model = get_fully_connected_model()

    history = model.fit(X_train, y_train, epochs=24, batch_size=32, validation_split=0.1) 

    # Save model with timestamp
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    #model_filename = f'model/my_model_{timestamp}.h5'
    model_filename = f'cross_test/my_model_{timestamp}.h5'

    model.save(model_filename)



# Predict on real data
DS, peaks = get_traces(num_samples, filename)

DS = DS[(num_samples-num_test_samples):num_samples]
peaks = peaks[(num_samples-num_test_samples):num_samples]

X_test = DS[:, (0+start_cut):(num_dist-end_cut)].reshape(num_test_samples, num_dist - (start_cut + end_cut), 1)
y_test = peaks[:, (0+start_cut):(num_dist-end_cut)].reshape(num_test_samples, num_dist - (start_cut + end_cut), 1)
num_dist -= (start_cut + end_cut)
X_test = normalize_data(X_test)


predictions = model.predict(X_test)

# Reshape predictions 
reshaped_predictions = predictions.reshape(num_test_samples, num_dist)
reshaped_ground_truth = y_test.reshape(num_test_samples, num_dist)


# Top-K Evaluation
top = [0, 0, 0, 0]

for i in range(num_test_samples):
    eval_pred = reshaped_predictions[i]
    eval_truth = reshaped_ground_truth[i]
    # returns the number of missed positions
    top5 = print_Top_K_Evaluation(eval_pred, eval_truth, round(num_dist*0.05))
    top10 = print_Top_K_Evaluation(eval_pred, eval_truth, round(num_dist*0.10))
    top15 = print_Top_K_Evaluation(eval_pred, eval_truth, round(num_dist*0.15))
    top20 = print_Top_K_Evaluation(eval_pred, eval_truth, round(num_dist*0.20))
    print()

    # count if all but 2 positions have been found for different K percentiles
    if(top5 <= 2): top[0] +=1
    if(top10 <= 2): top[1] +=1
    if(top15 <= 2): top[2] +=1
    if(top20 <= 2): top[3] +=1

print(f"top 5 : {top[0]} / {num_test_samples} -> {top[0]/num_test_samples}")
print(f"top 10 : {top[1]} / {num_test_samples} -> {top[1]/num_test_samples}")
print(f"top 15 : {top[2]} / {num_test_samples} -> {top[2]/num_test_samples}")
print(f"top 20 : {top[3]} / {num_test_samples} -> {top[3]/num_test_samples}")



