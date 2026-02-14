# ml_model.py
import pandas as pd
import numpy as np
import pickle
import os
import gzip
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
import warnings
warnings.filterwarnings('ignore')

class PEAnalysisMLModel:
    """
    Machine Learning model for PE file analysis based on the MalwareData dataset
    This class handles training, saving, loading, and prediction
    """

    def __init__(self, model_path='pe_malware_model.pkl', selector_path='feature_selector.pkl'):
        self.model = None
        self.feature_selector = None
        self.feature_names = None
        self.is_trained = False
        self.model_path = model_path
        self.selector_path = selector_path
        
        # Feature names from the MalwareData dataset (without Name, md5, legitimate)
        self.original_feature_names = [
            'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
            'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
            'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
            'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
            'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion',
            'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
            'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
            'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy',
            'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize',
            'SectionsMaxRawsize', 'SectionsMeanVirtualsize', 'SectionsMinVirtualsize',
            'SectionsMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal',
            'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy',
            'ResourcesMaxEntropy', 'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize',
            'LoadConfigurationSize', 'VersionInformationSize'
        ]
        
        # Try to load existing model
        self.load_model()
    
    def load_model(self):
        """Load trained model from disk"""
        if os.path.exists(self.model_path) and os.path.exists(self.selector_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.selector_path, 'rb') as f:
                    self.feature_selector = pickle.load(f)
                self.is_trained = True
                
                # Try to load feature names if they exist
                names_path = self.model_path.replace('.pkl', '_features.pkl')
                if os.path.exists(names_path):
                    with open(names_path, 'rb') as f:
                        self.feature_names = pickle.load(f)
                
                print(f"✓ Loaded PE analysis ML model from {self.model_path}")
                return True
            except Exception as e:
                print(f"✗ Error loading ML model: {e}")
                return False
        return False
    
    def save_model(self):
        """Save trained model to disk"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            with open(self.selector_path, 'wb') as f:
                pickle.dump(self.feature_selector, f)
            if self.feature_names:
                names_path = self.model_path.replace('.pkl', '_features.pkl')
                with open(names_path, 'wb') as f:
                    pickle.dump(self.feature_names, f)
            print(f"✓ Model saved to {self.model_path}")
            return True
        except Exception as e:
            print(f"✗ Error saving model: {e}")
            return False
    
    def train(self, csv_path='MalwareData.csv', use_gzipped=True, test_size=0.2, random_state=42):
        """
        Train the model using the MalwareData dataset
        
        Args:
            csv_path: Path to the CSV file
            use_gzipped: If True, look for .gz version if regular file doesn't exist
            test_size: Fraction of data to use for testing
            random_state: Random seed for reproducibility
        
        Returns:
            Dictionary with training metrics
        """
        try:
            # Handle gzipped files
            if use_gzipped and not os.path.exists(csv_path):
                gz_path = csv_path + '.gz'
                if os.path.exists(gz_path):
                    print(f"📦 Reading compressed dataset from {gz_path}")
                    with gzip.open(gz_path, 'rt') as f:
                        df = pd.read_csv(f, sep='|')
                else:
                    print(f"✗ Dataset not found at {csv_path} or {gz_path}")
                    return None
            else:
                print(f"📊 Reading dataset from {csv_path}")
                df = pd.read_csv(csv_path, sep='|')
            
            print(f"✓ Dataset loaded: {df.shape[0]} samples, {df.shape[1]} features")
            
            # Split into legitimate and malware samples for information
            legit_count = len(df[df['legitimate'] == 1])
            malware_count = len(df[df['legitimate'] == 0])
            print(f"   Legitimate: {legit_count}, Malware: {malware_count}")
            
            # Prepare features and target
            # Drop Name, md5, and legitimate columns
            X = df.drop(['Name', 'md5', 'legitimate'], axis=1).values
            y = df['legitimate'].values
            
            # Split data for training and testing
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            print("🔍 Selecting important features...")
            # Feature selection using ExtraTreesClassifier
            feat_selector = ExtraTreesClassifier(n_estimators=50, random_state=random_state, n_jobs=-1)
            feat_selector.fit(X_train, y_train)
            
            # Select features with importance > median
            self.feature_selector = SelectFromModel(feat_selector, prefit=True, threshold='median')
            X_train_selected = self.feature_selector.transform(X_train)
            X_test_selected = self.feature_selector.transform(X_test)
            
            # Get selected feature names
            selected_indices = self.feature_selector.get_support(indices=True)
            self.feature_names = [self.original_feature_names[i] for i in selected_indices]
            
            print(f"   Selected {len(self.feature_names)} important features")
            print(f"   Features: {', '.join(self.feature_names[:10])}...")
            
            # Train Random Forest classifier
            print("🌲 Training Random Forest model...")
            self.model = RandomForestClassifier(
                n_estimators=50,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=random_state,
                n_jobs=-1
            )
            self.model.fit(X_train_selected, y_train)
            
            # Evaluate on test set
            y_pred = self.model.predict(X_test_selected)
            y_proba = self.model.predict_proba(X_test_selected)
            
            # Calculate metrics
            accuracy = self.model.score(X_test_selected, y_test)
            cm = confusion_matrix(y_test, y_pred)
            
            # Calculate false positive and false negative rates
            tn, fp, fn, tp = cm.ravel()
            fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
            fnr = (fn / (fn + tp)) * 100 if (fn + tp) > 0 else 0
            
            metrics = {
                'accuracy': accuracy * 100,
                'false_positive_rate': fpr,
                'false_negative_rate': fnr,
                'precision': tp / (tp + fp) if (tp + fp) > 0 else 0,
                'recall': tp / (tp + fn) if (tp + fn) > 0 else 0,
                'confusion_matrix': cm.tolist(),
                'n_features': len(self.feature_names),
                'n_train': len(X_train),
                'n_test': len(X_test)
            }
            
            print(f"\n✓ Training complete!")
            print(f"   Accuracy: {metrics['accuracy']:.2f}%")
            print(f"   False Positive Rate: {metrics['false_positive_rate']:.2f}%")
            print(f"   False Negative Rate: {metrics['false_negative_rate']:.2f}%")
            print(f"   Precision: {metrics['precision']:.3f}")
            print(f"   Recall: {metrics['recall']:.3f}")
            
            self.is_trained = True
            self.save_model()
            
            return metrics
            
        except Exception as e:
            print(f"✗ Error training model: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def extract_pe_features(self, filepath):
        """
        Extract PE features from a file for prediction
        This matches the features used in the MalwareData dataset
        
        Args:
            filepath: Path to the PE file
        
        Returns:
            numpy array of features or None if extraction fails
        """
        try:
            pe = pefile.PE(filepath)
            
            # Initialize feature dictionary with default values
            features = {}
            for name in self.original_feature_names:
                features[name] = 0
            
            # Extract basic PE headers
            features['Machine'] = pe.FILE_HEADER.Machine
            features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
            features['Characteristics'] = pe.FILE_HEADER.Characteristics
            features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
            features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
            features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
            features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
            features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
            features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
            features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
            features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
            features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
            features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            
            # Section information
            sections = pe.sections
            features['SectionsNb'] = len(sections)
            
            if sections:
                # Section entropies
                entropies = [self._calculate_section_entropy(s) for s in sections]
                features['SectionsMeanEntropy'] = np.mean(entropies)
                features['SectionsMinEntropy'] = np.min(entropies)
                features['SectionsMaxEntropy'] = np.max(entropies)
                
                # Raw sizes
                raw_sizes = [s.SizeOfRawData for s in sections]
                features['SectionsMeanRawsize'] = np.mean(raw_sizes) if raw_sizes else 0
                features['SectionsMinRawsize'] = np.min(raw_sizes) if raw_sizes else 0
                features['SectionsMaxRawsize'] = np.max(raw_sizes) if raw_sizes else 0
                
                # Virtual sizes
                virtual_sizes = [s.Misc_VirtualSize for s in sections]
                features['SectionsMeanVirtualsize'] = np.mean(virtual_sizes) if virtual_sizes else 0
                features['SectionsMinVirtualsize'] = np.min(virtual_sizes) if virtual_sizes else 0
                features['SectionsMaxVirtualsize'] = np.max(virtual_sizes) if virtual_sizes else 0
            
            # Import information
            features['ImportsNbDLL'] = 0
            features['ImportsNb'] = 0
            features['ImportsNbOrdinal'] = 0
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    features['ImportsNb'] += len(entry.imports)
                    features['ImportsNbOrdinal'] += sum(1 for imp in entry.imports if imp.ordinal)
            
            # Export information
            features['ExportNb'] = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if pe.DIRECTORY_ENTRY_EXPORT.symbols else 0
            
            # Resource information
            features['ResourcesNb'] = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resources = []
                self._count_resources(pe.DIRECTORY_ENTRY_RESOURCE.entries, resources)
                features['ResourcesNb'] = len(resources)
            
            # Convert to numpy array in the correct order
            feature_vector = np.array([features[name] for name in self.original_feature_names])
            
            return feature_vector.reshape(1, -1)
            
        except Exception as e:
            print(f"Error extracting PE features from {filepath}: {e}")
            return None
    
    def _calculate_section_entropy(self, section):
        """Calculate entropy for a PE section"""
        try:
            data = section.get_data()
            if not data:
                return 0
            
            # Count byte frequencies
            byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
            byte_counts = byte_counts[byte_counts > 0]
            
            # Calculate entropy
            probs = byte_counts / len(data)
            entropy = -np.sum(probs * np.log2(probs))
            
            return entropy
        except:
            return 0
    
    def _count_resources(self, entries, resources):
        """Recursively count resources"""
        for entry in entries:
            if hasattr(entry, 'directory'):
                self._count_resources(entry.directory.entries, resources)
            else:
                resources.append(entry)
    
    def predict(self, filepath):
        """
        Predict if a file is malware using the trained model
        
        Args:
            filepath: Path to the PE file
        
        Returns:
            tuple: (is_malware, confidence, feature_importance)
        """
        if not self.is_trained or self.model is None:
            return False, 0.0, None
        
        try:
            # Extract features
            features = self.extract_pe_features(filepath)
            if features is None:
                return False, 0.0, None
            
            # Apply feature selection
            features_selected = self.feature_selector.transform(features)
            
            # Predict
            prediction = self.model.predict(features_selected)[0]
            probabilities = self.model.predict_proba(features_selected)[0]
            
            # probabilities[0] = probability of legitimate (class 0)
            # probabilities[1] = probability of malware (class 1)
            malware_probability = probabilities[1]
            is_malware = prediction == 0  # 0 = malware, 1 = legitimate in the dataset
            
            # Get feature importance for this prediction
            if hasattr(self.model, 'feature_importances_'):
                feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
            else:
                feature_importance = None
            
            return is_malware, malware_probability, feature_importance
            
        except Exception as e:
            print(f"Error predicting {filepath}: {e}")
            return False, 0.0, None
    
    def get_model_info(self):
        """Get information about the trained model"""
        if not self.is_trained:
            return {"status": "not_trained"}
        
        return {
            "status": "trained",
            "n_features": len(self.feature_names) if self.feature_names else 0,
            "model_type": type(self.model).__name__ if self.model else None,
            "feature_names": self.feature_names
        }


# ========== Utility function for easy model training ==========
def train_pe_model(csv_path='MalwareData.csv', use_gzipped=True):
    """
    Train the PE analysis model from the command line
    """
    print("=" * 60)
    print("🔬 PE Malware Detection Model Training")
    print("=" * 60)
    
    model = PEAnalysisMLModel()
    metrics = model.train(csv_path, use_gzipped=use_gzipped)
    
    if metrics:
        print("\n" + "=" * 60)
        print("✅ Training Successful!")
        print("=" * 60)
        print(f"Accuracy: {metrics['accuracy']:.2f}%")
        print(f"False Positive Rate: {metrics['false_positive_rate']:.2f}%")
        print(f"False Negative Rate: {metrics['false_negative_rate']:.2f}%")
        print(f"Precision: {metrics['precision']:.3f}")
        print(f"Recall: {metrics['recall']:.3f}")
        print(f"Features used: {metrics['n_features']}")
        print("=" * 60)
    else:
        print("\n❌ Training failed!")


# ========== If run directly, train the model ==========
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train PE Malware Detection Model')
    parser.add_argument('--csv', type=str, default='MalwareData.csv',
                        help='Path to MalwareData.csv (default: MalwareData.csv)')
    parser.add_argument('--no-gz', action='store_true',
                        help='Disable automatic .gz file handling')
    
    args = parser.parse_args()
    
    train_pe_model(args.csv, use_gzipped=not args.no_gz)