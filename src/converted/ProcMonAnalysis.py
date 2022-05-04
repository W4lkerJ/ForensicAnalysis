#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[1]:


import json
import pandas as pd


# # Config

# ## Paths

# In[80]:


current_malware = "GandCrabV4"


# In[81]:


project_root = "/home/jevenari/PycharmProjects/ForensicalAnalysis"


# In[82]:


config_path = "/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"
config = json.load(open(config_path, "r"))
config = config[current_malware]


# In[83]:


procmon_path = f"{config['Dynamic']}/{config['ProcessMonitor']}"


# In[84]:


regshot_path = f"{project_root}/data/{current_malware}/{config['Regshot']}"


# ## Pandas

# In[85]:


pd.set_option('display.min_rows', 1000)
pd.set_option("display.max_rows", 10000)


# # Process Monitor Analysis

# ## Load data

# In[86]:


df_procmon = pd.read_csv(procmon_path)


# In[87]:


df_procmon


# ## Get unique operations

# In[88]:


sorted(list(df_procmon["Operation"].unique()))


# ## Get Process Create/Process Exit/Process Start events)

# In[89]:


df_process_create = df_procmon.query("Operation == 'Process Create'")


# In[90]:


df_process_create


# In[91]:


df_process_start = df_procmon.query("Operation == 'Process Start'")


# In[92]:


df_process_start


# In[93]:


df_process_exit = df_procmon.query("Operation == 'Process Exit'")


# In[94]:


df_process_exit


# ## Get Thread Create/Thread Exit

# In[95]:


df_thread_create = df_procmon.query("Operation == 'Thread Create'")


# In[96]:


df_thread_create.count()


# In[97]:


df_thread_create


# In[98]:


df_thread_exit = df_procmon.query("Operation == 'Thread Exit'")


# In[99]:


df_thread_exit


# ## Get RegCreateKey/RegSetValue data

# In[100]:


df_reg_value_set = df_procmon.query("Operation == 'RegCreateKey'")


# In[101]:


df_reg_value_set


# In[102]:


df_reg_value_set = df_procmon.query("Operation == 'RegSetValue'")


# In[103]:


df_reg_value_set.count()


# In[104]:


df_reg_value_set


# ## Get loaded DLLs

# In[105]:


df_loaded_dlls = df_procmon.query("Operation == 'Load Image'")


# In[106]:


unique_dlls = pd.unique(df_loaded_dlls["Path"])


# In[107]:


df_unique_dlls = pd.DataFrame(unique_dlls, columns=["Path"])


# In[108]:


df_unique_dlls["DLL"] = df_unique_dlls["Path"].apply(lambda path: path.split("\\")[-1])


# In[109]:


df_unique_dlls.count()


# In[110]:


df_unique_dlls


# # Regshot Analysis

# ## Load data

# In[119]:


df_regshot_data = pd.read_csv(regshot_path, delimiter=";")


# ## Show unique types & operations

# In[120]:


sorted(df_regshot_data["Type"].unique())


# In[121]:


sorted(df_regshot_data["Operation"].unique())


# ## Files Created

# In[122]:


df_files_created = df_regshot_data.query("Type == 'File' & Operation == 'Added'")


# In[123]:


df_files_created


# In[124]:


df_files_created.count()


# ## Files modified

# In[125]:


df_files_modiefied = df_regshot_data.query("Type == 'File' & Operation == 'Modified'")


# In[126]:


df_files_modiefied


# In[127]:


df_files_modiefied.count()


# ## Files Deleted

# In[128]:


df_files_deleted = df_regshot_data.query("Type == 'File' & Operation == 'Deleted'")


# In[129]:


df_files_deleted


# In[130]:


df_files_deleted.count()


# ## Folders Created

# In[131]:


df_folders_created = df_regshot_data.query("Type == 'Folder' & Operation == 'Added'")


# In[132]:


df_folders_created


# In[133]:


df_folders_created.count()


# ## Folders modified

# In[134]:


df_folders_modified = df_regshot_data.query("Type == 'Folder' & Operation == 'Modified'")


# In[135]:


df_folders_modified


# In[136]:


df_folders_modified.count()


# ## Folders Deleted

# In[137]:


df_folders_deleted = df_regshot_data.query("Type == 'Folder' & Operation == 'Deleted'")


# In[138]:


df_folders_deleted


# In[139]:


df_folders_deleted.count()


# ## Registry Keys Created

# In[140]:


df_reg_keys_created = df_regshot_data.query("Type == 'Key' & Operation == 'Added'")


# In[141]:


df_reg_keys_created


# In[142]:


df_reg_keys_created.count()


# ## Registry Keys modified

# In[143]:


df_reg_keys_modfied = df_regshot_data.query("Type == 'Key' & Operation == 'Modified'")


# In[144]:


df_reg_keys_modfied


# In[145]:


df_reg_keys_modfied.count()


# ## Registry Keys Deleted

# In[146]:


df_reg_keys_deleted = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[147]:


df_reg_keys_deleted


# In[148]:


df_reg_keys_deleted.count()


# ## Registry Values Created
# <h4 style="color: red">CAUTION: This part could not be parsed correctly, since the actual values were distributed over multiple lines resulting in a random pattern, that was impossible to parse.</h4>

# In[149]:


df_reg_values_created = df_regshot_data.query("Type == 'Value' & Operation == 'Added'")


# In[150]:


df_reg_values_created


# In[151]:


df_reg_values_created.count()


# ## Registry Values modified

# In[152]:


df_reg_values_modified = df_regshot_data.query("Type == 'Value' & Operation == 'Modified'")


# In[153]:


df_reg_values_modified


# In[154]:


df_reg_values_modified.count()


# ## Registry Values Deleted

# In[155]:


df_reg_values_deleted = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[156]:


df_reg_values_deleted


# In[157]:


df_reg_values_deleted.count()


# ## Generate Read Flow

# In[158]:


read_data = {
    "Type": "File",
    "Operation": "Read",
    "Path": "C:\\Users\\Cuckoo\\Documents\\Images\\a-panther-is-seen-after-being-sedated-in-league-of-the-protection-of-animals-lpa-shelter-in-lille.jpg",
}
read_data_series = pd.Series(read_data)


# In[64]:


read_data_series


# In[65]:


df_files_deleted.iloc[16]


# In[66]:


df_files_created.iloc[18]


# In[75]:


data = [
    read_data_series,
    df_files_created.iloc[18],
    df_files_deleted.iloc[16],
]


# In[76]:


df_data = pd.DataFrame(data)


# In[77]:


df_data


# In[78]:


pd.options.display.width = 0


# In[79]:


from pandas import option_context

with option_context('display.max_colwidth', 400):
    display(df_data)


# In[ ]:




