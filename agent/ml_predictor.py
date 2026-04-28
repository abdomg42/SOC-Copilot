from ML.Windows.preprocess_inference import load_artifacts, predict

artifacts = load_artifacts("/home/yassine/Documents/S4_IAGI/Projet Metier/SOC-Copilot/ML/Windows/trained_models/training_meta_data")

def predict_with_original_data(df_raw):
    df_out = df_raw.copy()
    df_out["ML_prediction"] = predict(df_raw, artifacts)
    return df_out