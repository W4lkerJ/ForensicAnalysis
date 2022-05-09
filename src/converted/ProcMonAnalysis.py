#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[1]:


import json
import pandas as pd
from pandas import option_context


# # Config

# ## Paths

# In[3]:


current_malware = "Darkside"


# In[4]:


project_root = "/home/jevenari/PycharmProjects/ForensicalAnalysis"


# In[5]:


config_path = "/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"
config = json.load(open(config_path, "r"))
config = config[current_malware]


# In[6]:


procmon_path = f"{config['Dynamic']}/{config['ProcessMonitor']}"


# In[7]:


regshot_path = f"{project_root}/data/{current_malware}/{config['Regshot']}"


# ## Pandas

# In[8]:


pd.set_option('display.min_rows', 1000)
pd.set_option("display.max_rows", 10000)


# # Process Monitor Analysis

# ## Load data

# In[9]:


df_procmon = pd.read_csv(procmon_path)


# ## Get unique operations

# In[11]:


sorted(list(df_procmon["Operation"].unique()))


# ## Get Create File/ReadFile/ WriteFile/Close File

# ### Create

# In[12]:


df_create_file = df_procmon.query("Operation == 'CreateFile'")


# In[15]:


df_create_file.count()


# In[13]:


with option_context('display.max_colwidth', 400):
    display(df_create_file)


# ### Read

# In[16]:


df_read_file = df_procmon.query("Operation == 'ReadFile'")


# In[17]:


df_read_file.count()


# In[18]:


with option_context('display.max_colwidth', 400):
    display(df_read_file)


# ### Write

# In[19]:


df_write_file = df_procmon.query("Operation == 'WriteFile'")


# In[22]:


df_write_file.count()


# #### Get unique files written

# In[23]:


df_write_file["Path"].unique()


# In[ ]:





# In[26]:


df_write_file["FileName"] = df_write_file["Path"].apply(lambda path: path.split("\\")[-1])


# In[31]:


test = list(df_write_file["FileName"].unique())


# In[32]:


len(test)


# In[33]:


test


# In[27]:


with option_context('display.max_colwidth', 400):
    display(df_write_file)


# ### Close

# In[59]:


df_close_file = df_procmon.query("Operation == 'CloseFile'")


# In[60]:


with option_context('display.max_colwidth', 400):
    display(df_close_file)


# ## Get Process Create/Process Exit/Process Start events)

# In[34]:


df_process_create = df_procmon.query("Operation == 'Process Create'")


# In[45]:


with option_context('display.max_colwidth', 400):
    display(df_process_create)


# In[36]:


df_process_start = df_procmon.query("Operation == 'Process Start'")


# In[46]:


with option_context('display.max_colwidth', 400):
    display(df_process_start)


# In[38]:


df_process_exit = df_procmon.query("Operation == 'Process Exit'")


# In[47]:


with option_context('display.max_colwidth', 400):
    display(df_process_exit)


# ## Get Thread Create/Thread Exit

# In[40]:


df_thread_create = df_procmon.query("Operation == 'Thread Create'")


# In[41]:


df_thread_create.count()


# In[42]:


df_thread_create


# In[43]:


df_thread_exit = df_procmon.query("Operation == 'Thread Exit'")


# In[44]:


df_thread_exit


# ## Get RegCreateKey/RegSetValue data

# In[48]:


df_reg_key_create = df_procmon.query("Operation == 'RegCreateKey'")


# In[49]:


df_reg_key_create.count()


# In[50]:


with option_context('display.max_colwidth', 400):
    display(df_reg_key_create)


# In[51]:


df_reg_value_set = df_procmon.query("Operation == 'RegSetValue'")


# In[52]:


df_reg_value_set.count()


# In[53]:


with option_context('display.max_colwidth', 400):
    display(df_reg_value_set)


# ## Get RegQueryKey/RegQueryValue data

# In[54]:


df_reg_key_query = df_procmon.query("Operation == 'RegQueryKey'") 


# In[55]:


df_reg_key_query.count()


# In[70]:


with option_context('display.max_colwidth', 400):
    display(df_reg_key_query)


# In[56]:


df_reg_value_query = df_procmon.query("Operation == 'RegQueryValue'") 


# In[57]:


df_reg_value_query.count()


# In[73]:


with option_context('display.max_colwidth', 400):
    display(df_reg_value_query)


# ## Get loaded DLLs

# In[58]:


df_loaded_dlls = df_procmon.query("Operation == 'Load Image'")


# In[59]:


unique_dlls = pd.unique(df_loaded_dlls["Path"])


# In[60]:


df_unique_dlls = pd.DataFrame(unique_dlls, columns=["Path"])


# In[61]:


df_unique_dlls["DLL"] = df_unique_dlls["Path"].apply(lambda path: path.split("\\")[-1])


# In[62]:


df_unique_dlls.count()


# In[63]:


df_unique_dlls


# # Regshot Analysis

# ## Load data

# In[64]:


df_regshot_data = pd.read_csv(regshot_path, delimiter=";")


# ## Show unique types & operations

# In[65]:


sorted(df_regshot_data["Type"].unique())


# In[66]:


sorted(df_regshot_data["Operation"].unique())


# ## Files Created

# In[67]:


df_files_created = df_regshot_data.query("Type == 'File' & Operation == 'Added'")


# In[69]:


df_files_created.count()


# In[68]:


with option_context('display.max_colwidth', 400):
    display(df_files_created)


# In[74]:


df_files_created.count()


# ## Files modified

# In[77]:


df_files_modiefied = df_regshot_data.query("Type == 'File' & Operation == 'Modified'")


# In[78]:


df_files_modiefied.count()


# In[79]:


with option_context('display.max_colwidth', 400):
    display(df_files_modiefied)


# ## Files Deleted

# In[74]:


df_files_deleted = df_regshot_data.query("Type == 'File' & Operation == 'Deleted'")


# In[75]:


df_files_deleted.count()


# In[76]:


with option_context('display.max_colwidth', 400):
    display(df_files_deleted)


# ## Folders Created

# In[82]:


df_folders_created = df_regshot_data.query("Type == 'Folder' & Operation == 'Added'")


# In[83]:


df_folders_created.count()


# In[84]:


with option_context('display.max_colwidth', 400):
    display(df_folders_created)


# ## Folders modified

# In[85]:


df_folders_modified = df_regshot_data.query("Type == 'Folder' & Operation == 'Modified'")


# In[86]:


df_folders_modified.count()


# In[87]:


with option_context('display.max_colwidth', 400):
    display(df_folders_modified)


# ## Folders Deleted

# In[88]:


df_folders_deleted = df_regshot_data.query("Type == 'Folder' & Operation == 'Deleted'")


# In[89]:


df_folders_deleted.count()


# In[90]:


with option_context('display.max_colwidth', 400):
    display(df_folders_deleted)


# ## Registry Keys Created

# In[91]:


df_reg_keys_created = df_regshot_data.query("Type == 'Key' & Operation == 'Added'")


# In[92]:


df_reg_keys_created.count()


# In[93]:


with option_context('display.max_colwidth', 400):
    display(df_reg_keys_created)


# ## Registry Keys modified

# In[94]:


df_reg_keys_modfied = df_regshot_data.query("Type == 'Key' & Operation == 'Modified'")


# In[95]:


df_reg_keys_modfied.count()


# In[96]:


with option_context('display.max_colwidth', 400):
    display(df_reg_keys_modfied)


# ## Registry Keys Deleted

# In[97]:


df_reg_keys_deleted = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[98]:


df_reg_keys_deleted.count()


# In[99]:


with option_context('display.max_colwidth', 400):
    display(df_reg_keys_deleted)


# ## Registry Values Created
# <h4 style="color: red">CAUTION: This part could not be parsed correctly, since the actual values were distributed over multiple lines resulting in a random pattern, that was impossible to parse.</h4>

# In[100]:


df_reg_values_created = df_regshot_data.query("Type == 'Value' & Operation == 'Added'")


# In[101]:


df_reg_values_created.count()


# In[102]:


with option_context('display.max_colwidth', 400):
    display(df_reg_values_created)


# ## Registry Values modified

# In[103]:


df_reg_values_modified = df_regshot_data.query("Type == 'Value' & Operation == 'Modified'")


# In[104]:


df_reg_values_modified.count()


# In[105]:


with option_context('display.max_colwidth', 400):
    display(df_reg_values_modified)


# ## Registry Values Deleted

# In[106]:


df_reg_values_deleted = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[107]:


df_reg_values_deleted.count()


# In[108]:


with option_context('display.max_colwidth', 400):
    display(df_reg_values_deleted)


# ## Generate Read Flow

# In[72]:


read_data = {
    "Type": "File",
    "Operation": "Read",
    "Path": "C:\\Users\\Cuckoo\\Documents\\Images\\a-panther-is-seen-after-being-sedated-in-league-of-the-protection-of-animals-lpa-shelter-in-lille.jpg",
}
read_data_series = pd.Series(read_data)


# In[73]:


read_data_series


# In[74]:


df_files_deleted.iloc[16]


# In[ ]:


df_files_created.iloc[18]


# In[ ]:


data = [
    read_data_series,
    df_files_created.iloc[18],
    df_files_deleted.iloc[16],
]


# In[75]:


df_data = pd.DataFrame(data)


# In[77]:


df_data

