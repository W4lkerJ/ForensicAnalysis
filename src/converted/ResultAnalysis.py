#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[1]:


import json
import pandas as pd
from pandas import option_context


# # Config

# ## Paths

# In[2]:


current_malware = "Cerber"


# In[3]:


project_root = "/home/jevenari/PycharmProjects/ForensicalAnalysis"


# In[4]:


config_path = "/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"
config = json.load(open(config_path, "r"))
config = config[current_malware]


# In[5]:


procmon_path = f"{config['Dynamic']}/{config['ProcessMonitor']}"


# In[6]:


regshot_path = f"{project_root}/data/{current_malware}/{config['Regshot']}"


# ## Pandas

# In[7]:


pd.set_option('display.min_rows', 1000)
pd.set_option("display.max_rows", 10000)


# # Process Monitor Analysis

# ## Load data

# In[8]:


df_procmon = pd.read_csv(procmon_path)


# ## Get unique operations

# In[9]:


sorted(list(df_procmon["Operation"].unique()))


# ## Get Process Create/Process Exit/Process Start events)

# In[12]:


df_process_create = df_procmon.query("Operation == 'Process Create'")


# In[13]:


df_process_create_display = df_process_create[["Time of Day", "Process Name", "PID", "Operation", "Result", "Detail"]]


# In[14]:


with option_context('display.max_colwidth', 400):
    display(df_process_create_display)


# In[15]:


df_process_start = df_procmon.query("Operation == 'Process Start'")


# In[16]:


with option_context('display.max_colwidth', 400):
    display(df_process_start)


# In[17]:


df_process_exit = df_procmon.query("Operation == 'Process Exit'")


# In[18]:


with option_context('display.max_colwidth', 400):
    display(df_process_exit)


# ## Get Thread Create/Thread Exit

# In[19]:


df_thread_create = df_procmon.query("Operation == 'Thread Create'")


# In[20]:


df_thread_create.count()


# In[21]:


df_thread_create


# In[22]:


df_thread_exit = df_procmon.query("Operation == 'Thread Exit'")


# In[23]:


df_thread_exit


# ## Get RegCreateKey/RegSetValue data

# In[24]:


df_reg_key_create = df_procmon.query("Operation == 'RegCreateKey'")


# In[25]:


df_reg_key_create.count()


# In[26]:


with option_context('display.max_colwidth', 400):
    display(df_reg_key_create)


# In[27]:


df_reg_value_set = df_procmon.query("Operation == 'RegSetValue'")


# In[28]:


df_reg_value_set.count()


# In[29]:


with option_context('display.max_colwidth', 400):
    display(df_reg_value_set)


# ## Get RegQueryKey/RegQueryValue data

# In[30]:


df_reg_key_query = df_procmon.query("Operation == 'RegQueryKey'") 


# In[31]:


df_reg_key_query.count()


# In[32]:


with option_context('display.max_colwidth', 400):
    display(df_reg_key_query)


# In[33]:


df_reg_value_query = df_procmon.query("Operation == 'RegQueryValue'") 


# In[34]:


df_reg_value_query.count()


# In[35]:


with option_context('display.max_colwidth', 400):
    display(df_reg_value_query)


# ## Get loaded DLLs

# In[36]:


df_loaded_dlls = df_procmon.query("Operation == 'Load Image'")


# In[37]:


unique_dlls = pd.unique(df_loaded_dlls["Path"])


# In[38]:


df_unique_dlls = pd.DataFrame(unique_dlls, columns=["Path"])


# In[39]:


df_unique_dlls["DLL"] = df_unique_dlls["Path"].apply(lambda path: path.split("\\")[-1])


# In[40]:


df_unique_dlls.count()


# In[41]:


df_unique_dlls


# # Regshot Analysis

# ## Load data

# In[21]:


df_regshot_data = pd.read_csv(regshot_path, delimiter=";")


# ## Show unique types & operations

# In[22]:


sorted(df_regshot_data["Type"].unique())


# In[23]:


sorted(df_regshot_data["Operation"].unique())


# ## Files Created

# In[24]:


df_files_created = df_regshot_data.query("Type == 'File' & Operation == 'Added'")


# In[25]:


df_files_created.count()


# In[26]:


with option_context('display.max_colwidth', 400):
    display(df_files_created)


# In[50]:


df_files_created.count()


# ## Files modified

# In[27]:


df_files_modiefied = df_regshot_data.query("Type == 'File' & Operation == 'Modified'")


# In[28]:


df_files_modiefied.count()


# In[29]:


with option_context('display.max_colwidth', 400):
    display(df_files_modiefied)


# ## Files Deleted

# In[30]:


df_files_deleted = df_regshot_data.query("Type == 'File' & Operation == 'Deleted'")


# In[31]:


df_files_deleted.count()


# In[32]:


with option_context('display.max_colwidth', 400):
    display(df_files_deleted)


# ## Folders Created

# In[57]:


df_folders_created = df_regshot_data.query("Type == 'Folder' & Operation == 'Added'")


# In[58]:


df_folders_created.count()


# In[59]:


with option_context('display.max_colwidth', 400):
    display(df_folders_created)


# ## Folders modified

# In[60]:


df_folders_modified = df_regshot_data.query("Type == 'Folder' & Operation == 'Modified'")


# In[61]:


df_folders_modified.count()


# In[62]:


with option_context('display.max_colwidth', 400):
    display(df_folders_modified)


# ## Folders Deleted

# In[63]:


df_folders_deleted = df_regshot_data.query("Type == 'Folder' & Operation == 'Deleted'")


# In[64]:


df_folders_deleted.count()


# In[65]:


with option_context('display.max_colwidth', 400):
    display(df_folders_deleted)


# ## Registry Keys Created

# In[66]:


df_reg_keys_created = df_regshot_data.query("Type == 'Key' & Operation == 'Added'")


# In[67]:


df_reg_keys_created.count()


# In[68]:


with option_context('display.max_colwidth', 400):
    display(df_reg_keys_created)


# ## Registry Keys modified

# In[69]:


df_reg_keys_modfied = df_regshot_data.query("Type == 'Key' & Operation == 'Modified'")


# In[70]:


df_reg_keys_modfied.count()


# In[71]:


with option_context('display.max_colwidth', 400):
    display(df_reg_keys_modfied)


# ## Registry Keys Deleted

# In[72]:


df_reg_keys_deleted = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[73]:


df_reg_keys_deleted.count()


# In[74]:


with option_context('display.max_colwidth', 400):
    display(df_reg_keys_deleted)


# ## Registry Values Created
# <h4 style="color: red">CAUTION: This part could not be parsed correctly, since the actual values were distributed over multiple lines resulting in a random pattern, that was impossible to parse.</h4>

# In[75]:


df_reg_values_created = df_regshot_data.query("Type == 'Value' & Operation == 'Added'")


# In[76]:


df_reg_values_created.count()


# In[77]:


with option_context('display.max_colwidth', 400):
    display(df_reg_values_created)


# ## Registry Values modified

# In[78]:


df_reg_values_modified = df_regshot_data.query("Type == 'Value' & Operation == 'Modified'")


# In[79]:


df_reg_values_modified.count()


# In[80]:


with option_context('display.max_colwidth', 400):
    display(df_reg_values_modified)


# ## Registry Values Deleted

# In[81]:


df_reg_values_deleted = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[82]:


df_reg_values_deleted.count()


# In[83]:


with option_context('display.max_colwidth', 400):
    display(df_reg_values_deleted)

